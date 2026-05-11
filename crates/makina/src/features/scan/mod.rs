//! `POST /api/scan` — run all detectors in parallel, blend GBDT
//! confidence into each finding, and persist embeddings when learning
//! writes are enabled.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

use crate::api::models::{Finding, Language, ScanRequest, ScanResponse};
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
    let code_hash = format!("{:x}", Sha256::digest(req.code.as_bytes()));
    let lang_str = language_hint(&req.language);
    let lines = req.code.lines().count();

    info!(scan_id = %scan_id, language = lang_str, lines, "scan start");

    let ml = MlClient::new();
    let mut findings = run_detectors(&ml, &req_id.0, &req.code, &req.language).await;
    let scoring = ScoringContext {
        req_id: &req_id.0,
        code: &req.code,
        language: &req.language,
        lang_str,
        code_hash: &code_hash,
        persist_findings: !flags.public_mode,
    };
    let gbdt_applied = score_and_store_findings(&ml, scoring, &mut findings).await;

    info!(
        scan_id = %scan_id,
        findings = findings.len(),
        gbdt_applied,
        "scan done"
    );

    Ok(Json(ScanResponse {
        scan_id,
        findings,
        language: req.language,
        lines_scanned: lines,
    }))
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

fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut deduped: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if let Some(pos) = deduped
            .iter()
            .position(|existing| same_issue(existing, &finding))
        {
            if should_replace(&finding, &deduped[pos]) {
                deduped[pos] = finding;
            }
        } else {
            deduped.push(finding);
        }
    }
    deduped
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
    use crate::api::models::Severity;

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
}
