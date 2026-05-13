//! `POST /api/scan` — run all detectors in parallel, blend GBDT
//! confidence into each finding, and persist embeddings when learning
//! writes are enabled.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::api::models::{
    Finding, Language, ProjectScanFile, ProjectScanFileResult, ProjectScanRequest,
    ProjectScanResponse, ScanRequest, ScanResponse,
};
use crate::flags::Flags;
use crate::infra::ml::{bytes_to_f32_vec, language_hint, MlClient};
use crate::logging::RequestId;
use crate::store;

pub async fn scan(
    Extension(req_id): Extension<RequestId>,
    Extension(flags): Extension<Flags>,
    Json(req): Json<ScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scan_id = Uuid::new_v4().to_string();

    info!(
        scan_id = %scan_id,
        language = language_hint(&req.language),
        lines = count_code_lines(&req.code),
        "scan start"
    );

    let ml = MlClient::new();
    let outcome = scan_code(&ml, &req_id.0, flags, scan_id, &req.code, &req.language).await;

    info!(
        scan_id = %outcome.scan_id,
        findings = outcome.findings.len(),
        gbdt_applied = outcome.gbdt_applied,
        "scan done"
    );

    Ok(Json(ScanResponse {
        scan_id: outcome.scan_id,
        findings: outcome.findings,
        language: req.language,
        lines_scanned: outcome.lines_scanned,
    }))
}

pub async fn scan_project(
    Extension(req_id): Extension<RequestId>,
    Extension(flags): Extension<Flags>,
    Json(req): Json<ProjectScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scan_id = format!("project-{}", Uuid::new_v4());
    let total_lines = req
        .files
        .iter()
        .map(|file| count_code_lines(&file.code))
        .sum();
    let project_language = project_language(&req.files);
    let mut grouped: HashMap<Language, Vec<usize>> = HashMap::new();
    let mut file_results: Vec<ProjectScanFileResult> = req
        .files
        .iter()
        .map(|file| ProjectScanFileResult {
            path: file.path.clone(),
            scan_id: scan_id.clone(),
            language: file_language(file),
            lines_scanned: count_code_lines(&file.code),
            findings: vec![],
        })
        .collect();

    for (idx, file) in req.files.iter().enumerate() {
        if file.code.trim().is_empty() {
            continue;
        }
        grouped.entry(file_language(file)).or_default().push(idx);
    }

    info!(
        scan_id = %scan_id,
        files = req.files.len(),
        groups = grouped.len(),
        lines = total_lines,
        "project scan start"
    );

    let ml = MlClient::new();
    for (language, indices) in grouped {
        let (project_code, source_map) = build_project_code(&req.files, &indices, &language);
        let group_scan_id = format!("{}:{}", scan_id, language_hint(&language));
        let outcome = scan_code(
            &ml,
            &req_id.0,
            flags,
            group_scan_id,
            &project_code,
            &language,
        )
        .await;

        for finding in outcome.findings {
            if let Some((file_index, remapped)) = remap_project_finding(finding, &source_map) {
                file_results[file_index].findings.push(remapped);
            }
        }
    }

    let finding_count: usize = file_results.iter().map(|file| file.findings.len()).sum();
    info!(
        scan_id = %scan_id,
        files = file_results.len(),
        findings = finding_count,
        "project scan done"
    );

    Ok(Json(ProjectScanResponse {
        scan_id,
        files: file_results,
        language: project_language,
        lines_scanned: total_lines,
    }))
}

struct ScanOutcome {
    scan_id: String,
    findings: Vec<Finding>,
    lines_scanned: usize,
    gbdt_applied: bool,
}

async fn scan_code(
    ml: &MlClient,
    req_id: &str,
    flags: Flags,
    scan_id: String,
    code: &str,
    language: &Language,
) -> ScanOutcome {
    let code_hash = format!("{:x}", Sha256::digest(code.as_bytes()));
    let lang_str = language_hint(language);
    let mut findings = run_detectors(ml, req_id, code, language).await;
    let scoring = ScoringContext {
        req_id,
        code,
        language,
        lang_str,
        code_hash: &code_hash,
        persist_findings: !flags.public_mode,
    };
    let gbdt_applied = score_and_store_findings(ml, scoring, &mut findings).await;

    ScanOutcome {
        scan_id,
        findings,
        lines_scanned: count_code_lines(code),
        gbdt_applied,
    }
}

async fn run_detectors(
    ml: &MlClient,
    req_id: &str,
    code: &str,
    language: &Language,
) -> Vec<Finding> {
    let (semgrep, analyze, taint, property) = tokio::join!(
        ml.semgrep(req_id, code, language),
        ml.analyze(req_id, code, language),
        ml.taint(req_id, code, language),
        ml.property_patterns(req_id, code, language),
    );

    let capacity = semgrep.len() + analyze.len() + taint.len() + property.len();
    let mut findings = Vec::with_capacity(capacity);
    findings.extend(semgrep);
    findings.extend(analyze);
    findings.extend(taint);
    findings.extend(property);
    dedupe_findings(findings)
}

#[derive(Debug, Clone)]
struct SourceMapEntry {
    file_index: usize,
    path: String,
    start_line: u32,
    end_line: u32,
}

impl SourceMapEntry {
    fn contains(&self, line: u32) -> bool {
        line >= self.start_line && line <= self.end_line
    }

    fn local_line(&self, line: u32) -> u32 {
        line.saturating_sub(self.start_line).saturating_add(1)
    }
}

fn file_language(file: &ProjectScanFile) -> Language {
    file.language.clone().unwrap_or(Language::Auto)
}

fn project_language(files: &[ProjectScanFile]) -> Language {
    let mut languages = files.iter().map(file_language);
    let Some(first) = languages.next() else {
        return Language::Auto;
    };
    if languages.all(|language| language == first) {
        first
    } else {
        Language::Auto
    }
}

fn count_code_lines(code: &str) -> usize {
    if code.is_empty() {
        0
    } else {
        code.lines().count()
    }
}

fn comment_prefix(language: &Language) -> &'static str {
    match language {
        Language::Python | Language::Ruby => "#",
        _ => "//",
    }
}

fn build_project_code(
    files: &[ProjectScanFile],
    indices: &[usize],
    language: &Language,
) -> (String, Vec<SourceMapEntry>) {
    let mut code = String::new();
    let mut source_map = Vec::with_capacity(indices.len());
    let mut cursor_line: u32 = 1;
    let comment = comment_prefix(language);

    for idx in indices {
        let file = &files[*idx];
        let line_count = count_code_lines(&file.code) as u32;
        code.push_str(&format!("{comment} File: {}\n", file.path));

        let start_line = cursor_line + 1;
        let end_line = start_line + line_count.saturating_sub(1);
        source_map.push(SourceMapEntry {
            file_index: *idx,
            path: file.path.clone(),
            start_line,
            end_line,
        });

        code.push_str(&file.code);
        if !file.code.ends_with('\n') {
            code.push('\n');
        }
        code.push('\n');
        cursor_line += line_count + 2;
    }

    (code, source_map)
}

fn entry_for_line(source_map: &[SourceMapEntry], line: u32) -> Option<&SourceMapEntry> {
    source_map.iter().find(|entry| entry.contains(line))
}

fn remap_trace_graph(finding: &mut Finding, source_map: &[SourceMapEntry]) {
    let Some(graph) = finding.trace_graph.as_mut() else {
        return;
    };

    for node in &mut graph.nodes {
        let Some(line_start) = node.line_start else {
            continue;
        };
        let Some(entry) = entry_for_line(source_map, line_start) else {
            continue;
        };

        node.file = Some(entry.path.clone());
        node.line_start = Some(entry.local_line(line_start));
        node.line_end = node.line_end.map(|line_end| {
            if entry.contains(line_end) {
                entry.local_line(line_end)
            } else {
                entry.local_line(line_start)
            }
        });
    }
}

fn remap_exploration_plan(finding: &mut Finding, source_map: &[SourceMapEntry]) {
    let Some(plan) = finding.exploration_plan.as_mut() else {
        return;
    };

    for step in &mut plan.steps {
        let Some(line_start) = step.line_start else {
            continue;
        };
        let Some(entry) = entry_for_line(source_map, line_start) else {
            continue;
        };

        step.file = Some(entry.path.clone());
        step.line_start = Some(entry.local_line(line_start));
        step.line_end = step.line_end.map(|line_end| {
            if entry.contains(line_end) {
                entry.local_line(line_end)
            } else {
                entry.local_line(line_start)
            }
        });
    }
}

fn remap_project_finding(
    mut finding: Finding,
    source_map: &[SourceMapEntry],
) -> Option<(usize, Finding)> {
    let source_entry = entry_for_line(source_map, finding.line_start);
    let sink_entry = entry_for_line(source_map, finding.line_end).or(source_entry)?;

    let local_sink_line = sink_entry.local_line(finding.line_end);
    let local_start_line = match source_entry {
        Some(entry) if entry.file_index == sink_entry.file_index => {
            entry.local_line(finding.line_start)
        }
        _ => local_sink_line,
    };
    finding.line_start = local_start_line.min(local_sink_line);
    finding.line_end = local_start_line.max(local_sink_line);
    remap_trace_graph(&mut finding, source_map);
    remap_exploration_plan(&mut finding, source_map);

    if let Some(source_entry) = source_entry {
        if source_entry.file_index != sink_entry.file_index {
            finding.message = format!(
                "Cross-file flow: {} -> {}. {}",
                source_entry.path, sink_entry.path, finding.message
            );
            finding.code_snippet = format!(
                "{} Source file: {}\n{} Sink file: {}\n{}",
                comment_prefix(&Language::Auto),
                source_entry.path,
                comment_prefix(&Language::Auto),
                sink_entry.path,
                finding.code_snippet
            );
        }
    }

    Some((sink_entry.file_index, finding))
}

fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut deduped: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if let Some(pos) = deduped
            .iter()
            .position(|existing| same_issue(existing, &finding))
        {
            if should_replace(&finding, &deduped[pos]) {
                let mut replacement = finding;
                merge_supporting_evidence(&mut replacement, &deduped[pos]);
                deduped[pos] = replacement;
            } else {
                merge_supporting_evidence(&mut deduped[pos], &finding);
            }
        } else {
            deduped.push(finding);
        }
    }
    deduped
}

fn merge_supporting_evidence(target: &mut Finding, source: &Finding) {
    if target.trace_graph.is_none() {
        target.trace_graph = source.trace_graph.clone();
    }
    if target.exploration_plan.is_none() {
        target.exploration_plan = source.exploration_plan.clone();
    }
}

fn same_issue(a: &Finding, b: &Finding) -> bool {
    canonical_rule(a) == canonical_rule(b) && ranges_touch(a, b)
}

fn canonical_rule(finding: &Finding) -> &str {
    finding.cwe.as_deref().unwrap_or(&finding.rule_id)
}

fn ranges_touch(a: &Finding, b: &Finding) -> bool {
    const LINE_TOLERANCE: u32 = 2;
    let a_end = a.line_end.max(a.line_start);
    let b_end = b.line_end.max(b.line_start);
    a.line_start <= b_end.saturating_add(LINE_TOLERANCE)
        && b.line_start <= a_end.saturating_add(LINE_TOLERANCE)
}

fn should_replace(candidate: &Finding, current: &Finding) -> bool {
    let candidate_severity = severity_rank(&candidate.severity);
    let current_severity = severity_rank(&current.severity);
    if candidate_severity != current_severity {
        return candidate_severity > current_severity;
    }

    let candidate_source = source_rank(&candidate.source);
    let current_source = source_rank(&current.source);
    if candidate_source != current_source {
        return candidate_source > current_source;
    }

    const CONFIDENCE_EPSILON: f32 = 0.01;
    if (candidate.confidence - current.confidence).abs() > CONFIDENCE_EPSILON {
        return candidate.confidence > current.confidence;
    }

    span_len(candidate) < span_len(current)
}

fn severity_rank(severity: &crate::api::models::Severity) -> u8 {
    match severity {
        crate::api::models::Severity::Critical => 4,
        crate::api::models::Severity::High => 3,
        crate::api::models::Severity::Medium => 2,
        crate::api::models::Severity::Low => 1,
    }
}

fn source_rank(source: &str) -> u8 {
    match source {
        "taint" => 4,
        "semgrep" => 3,
        "property" => 2,
        "ml" => 1,
        _ => 0,
    }
}

fn span_len(finding: &Finding) -> u32 {
    finding
        .line_end
        .max(finding.line_start)
        .saturating_sub(finding.line_start)
}

struct ScoringContext<'a> {
    req_id: &'a str,
    code: &'a str,
    language: &'a Language,
    lang_str: &'a str,
    code_hash: &'a str,
    persist_findings: bool,
}

async fn score_and_store_findings(
    ml: &MlClient,
    ctx: ScoringContext<'_>,
    findings: &mut [Finding],
) -> bool {
    if findings.is_empty() {
        return false;
    }

    let line_starts: Vec<u32> = findings.iter().map(|f| f.line_start).collect();
    let embeddings = ml
        .embed_with_graph(ctx.req_id, ctx.code, ctx.language, &line_starts)
        .await;
    let float_vecs: Vec<Vec<f32>> = embeddings.iter().map(|v| bytes_to_f32_vec(v)).collect();
    let gbdt_scores = ml.predict_batch(ctx.req_id, float_vecs).await;
    let gbdt_applied = gbdt_scores.is_some();

    for (i, finding) in findings.iter_mut().enumerate() {
        if let Some(ref scores) = gbdt_scores {
            if let Some(Some(gbdt)) = scores.get(i) {
                apply_gbdt_score(finding, *gbdt);
            }
        }

        let emb = embeddings
            .get(i)
            .filter(|v| !v.is_empty())
            .map(|v| v.as_slice());
        if ctx.persist_findings {
            save_live_finding(finding, ctx.code_hash, ctx.lang_str, emb);
        }
    }

    gbdt_applied
}

fn apply_gbdt_score(finding: &mut Finding, gbdt: f32) {
    let blended = 0.5 * finding.confidence + 0.5 * gbdt;
    finding.confidence = blended;
    finding.is_uncertain = (0.40..=0.60).contains(&blended);
}

fn save_live_finding(finding: &Finding, code_hash: &str, lang_str: &str, emb: Option<&[u8]>) {
    let _ = store::save_finding(
        &finding.id,
        code_hash,
        &finding.rule_id,
        lang_str,
        finding.line_start,
        finding.confidence,
        emb,
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{
        ExplorationPlan, ExplorationStep, Severity, TraceGraph, TraceGraphNode,
    };

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            rule_id: "rule".to_string(),
            message: "finding".to_string(),
            severity: Severity::High,
            line_start: 10,
            line_end: 10,
            code_snippet: String::new(),
            confidence: 0.75,
            is_uncertain: false,
            cwe: Some("CWE-78".to_string()),
            source: "taint".to_string(),
            trace_graph: None,
            exploration_plan: None,
        }
    }

    #[test]
    fn dedupe_prefers_taint_path_over_semgrep_for_same_issue() {
        let mut semgrep = finding("semgrep");
        semgrep.rule_id = "semgrep-cmdi".to_string();
        semgrep.line_start = 12;
        semgrep.line_end = 12;
        semgrep.confidence = 0.85;
        semgrep.source = "semgrep".to_string();

        let mut taint = finding("taint");
        taint.rule_id = "taint-cmdi".to_string();
        taint.line_end = 14;
        taint.confidence = 0.75;

        let out = dedupe_findings(vec![semgrep, taint]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "taint");
    }

    #[test]
    fn dedupe_uses_confidence_within_same_source_rank() {
        let mut low = finding("low");
        low.source = "ml".to_string();
        low.confidence = 0.50;

        let mut high = finding("high");
        high.source = "ml".to_string();
        high.confidence = 0.80;

        let out = dedupe_findings(vec![low, high]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "high");
    }

    #[test]
    fn dedupe_preserves_trace_graph_from_lower_ranked_duplicate() {
        let mut ml = finding("ml");
        ml.cwe = Some("CWE-89".to_string());
        ml.severity = Severity::Critical;
        ml.source = "ml".to_string();

        let mut taint = finding("taint");
        taint.cwe = Some("CWE-89".to_string());
        taint.severity = Severity::High;
        taint.source = "taint".to_string();
        taint.trace_graph = Some(TraceGraph {
            nodes: vec![TraceGraphNode {
                id: "source:handler".to_string(),
                kind: "source".to_string(),
                label: "handler".to_string(),
                file: None,
                line_start: Some(10),
                line_end: Some(10),
                detail: None,
            }],
            edges: vec![],
        });
        taint.exploration_plan = Some(ExplorationPlan {
            kind: "source_to_sink".to_string(),
            title: "Validate path".to_string(),
            objective: "Confirm reachability".to_string(),
            priority: 0.82,
            rationale: "Taint path found".to_string(),
            steps: vec![],
            feedback_signals: vec![],
            required_evidence: vec![],
        });

        let out = dedupe_findings(vec![ml, taint]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "ml");
        assert!(out[0].trace_graph.is_some());
        assert!(out[0].exploration_plan.is_some());
    }

    #[test]
    fn dedupe_keeps_same_cwe_when_ranges_are_far_apart() {
        let mut first = finding("first");
        first.cwe = Some("CWE-89".to_string());
        first.rule_id = "sql-one".to_string();
        first.confidence = 0.85;
        first.source = "semgrep".to_string();
        first.severity = Severity::Critical;

        let mut second = finding("second");
        second.cwe = Some("CWE-89".to_string());
        second.rule_id = "sql-two".to_string();
        second.line_start = 40;
        second.line_end = 40;
        second.confidence = 0.85;
        second.source = "semgrep".to_string();
        second.severity = Severity::Critical;

        let out = dedupe_findings(vec![first, second]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedupe_uses_rule_id_when_cwe_is_missing() {
        let mut first = finding("first");
        first.cwe = None;
        first.rule_id = "hardcoded-secret".to_string();
        first.line_start = 20;
        first.line_end = 20;
        first.confidence = 0.50;
        first.source = "ml".to_string();
        first.severity = Severity::Medium;

        let mut second = finding("second");
        second.cwe = None;
        second.rule_id = "hardcoded-secret".to_string();
        second.line_start = 21;
        second.line_end = 21;
        second.confidence = 0.60;
        second.source = "ml".to_string();
        second.severity = Severity::Medium;

        let out = dedupe_findings(vec![first, second]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "second");
    }

    #[test]
    fn project_code_preserves_file_line_map() {
        let files = vec![
            ProjectScanFile {
                path: "app.py".to_string(),
                code: "def source():\n    pass\n".to_string(),
                language: Some(Language::Python),
            },
            ProjectScanFile {
                path: "db.py".to_string(),
                code: "def sink():\n    cursor.execute(query)\n".to_string(),
                language: Some(Language::Python),
            },
        ];

        let (code, source_map) = build_project_code(&files, &[0, 1], &Language::Python);

        assert!(code.contains("# File: app.py"));
        assert!(code.contains("# File: db.py"));
        assert_eq!(source_map[0].start_line, 2);
        assert_eq!(source_map[0].end_line, 3);
        assert_eq!(source_map[1].start_line, 6);
        assert_eq!(source_map[1].end_line, 7);
    }

    #[test]
    fn remap_project_finding_assigns_cross_file_flow_to_sink_file() {
        let source_map = vec![
            SourceMapEntry {
                file_index: 0,
                path: "source.py".to_string(),
                start_line: 2,
                end_line: 4,
            },
            SourceMapEntry {
                file_index: 1,
                path: "sink.py".to_string(),
                start_line: 7,
                end_line: 9,
            },
        ];
        let mut flow = finding("flow");
        flow.line_start = 3;
        flow.line_end = 8;
        flow.message = "SQL Injection".to_string();
        flow.trace_graph = Some(crate::api::models::TraceGraph {
            nodes: vec![
                crate::api::models::TraceGraphNode {
                    id: "source".to_string(),
                    kind: "source".to_string(),
                    label: "read_name".to_string(),
                    file: None,
                    line_start: Some(3),
                    line_end: Some(4),
                    detail: None,
                },
                crate::api::models::TraceGraphNode {
                    id: "sink".to_string(),
                    kind: "sink".to_string(),
                    label: "run_query".to_string(),
                    file: None,
                    line_start: Some(8),
                    line_end: Some(9),
                    detail: None,
                },
            ],
            edges: vec![],
        });
        flow.exploration_plan = Some(ExplorationPlan {
            kind: "source_to_sink".to_string(),
            title: "Validate path".to_string(),
            objective: "Confirm reachability".to_string(),
            priority: 0.82,
            rationale: "Taint path found".to_string(),
            steps: vec![
                ExplorationStep {
                    id: "source".to_string(),
                    kind: "source".to_string(),
                    label: "read_name".to_string(),
                    file: None,
                    line_start: Some(3),
                    line_end: Some(4),
                    detail: None,
                },
                ExplorationStep {
                    id: "sink".to_string(),
                    kind: "sink".to_string(),
                    label: "run_query".to_string(),
                    file: None,
                    line_start: Some(8),
                    line_end: Some(9),
                    detail: None,
                },
            ],
            feedback_signals: vec![],
            required_evidence: vec![],
        });

        let (file_index, remapped) = remap_project_finding(flow, &source_map).unwrap();

        assert_eq!(file_index, 1);
        assert_eq!(remapped.line_start, 2);
        assert_eq!(remapped.line_end, 2);
        assert!(remapped.message.contains("source.py -> sink.py"));
        let graph = remapped.trace_graph.unwrap();
        assert_eq!(graph.nodes[0].file.as_deref(), Some("source.py"));
        assert_eq!(graph.nodes[0].line_start, Some(2));
        assert_eq!(graph.nodes[1].file.as_deref(), Some("sink.py"));
        assert_eq!(graph.nodes[1].line_start, Some(2));
        let plan = remapped.exploration_plan.unwrap();
        assert_eq!(plan.steps[0].file.as_deref(), Some("source.py"));
        assert_eq!(plan.steps[0].line_start, Some(2));
        assert_eq!(plan.steps[1].file.as_deref(), Some("sink.py"));
        assert_eq!(plan.steps[1].line_start, Some(2));
    }
}
