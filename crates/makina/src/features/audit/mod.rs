//! `POST /api/audit/run` — run the server-defined LLM audit workflow.
//!
//! The Rust core owns workflow orchestration and prompt assembly. The
//! Python ML service remains the provider adapter that calls the official
//! OpenAI / Anthropic SDKs. API keys are request-scoped and never persisted.

use std::time::Instant;

use axum::{
    extract::{Extension, Json},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::models::{
    AuditReportSection, AuditRunRequest, AuditRunResponse, AuditStepRunRequest, AuditStepStatus,
    AuditWorkflowResult, Finding,
};
use crate::infra::ml::{language_hint, MlClient};
use crate::logging::RequestId;

const CODE_CHAR_LIMIT: usize = 18_000;
const FINDING_LIMIT: usize = 40;
const SYSTEM_PROMPT: &str = concat!(
    "You are Makina Audit, a security review assistant for scanner output.\n",
    "Use only the submitted code, scanner findings, and prior audit step outputs.\n",
    "Separate confirmed evidence from hypotheses.\n",
    "Do not claim a vulnerability is confirmed without a concrete source, path, and sink.\n",
    "When discussing proof of concept material, keep it minimal, non-destructive, and scoped to reproduction evidence.\n",
    "When a JSON schema or structured-output tool is supplied, return only data that conforms to it."
);

struct WorkflowStep {
    id: &'static str,
    title: &'static str,
    prompt: &'static str,
}

const WORKFLOW: &[WorkflowStep] = &[
    WorkflowStep {
        id: "triage",
        title: "Evidence Triage",
        prompt: concat!(
            "Group the scanner findings into confirmed candidates, likely false positives, and needs-review items. ",
            "Use scanner metadata as model-augmented evidence, not as ground truth. ",
            "For each candidate, identify the CWE, relevant lines, security boundary, and the missing evidence needed before reporting."
        ),
    },
    WorkflowStep {
        id: "trace",
        title: "Trace Validation",
        prompt: concat!(
            "Validate the high-priority candidates with a source-to-sink review. ",
            "For each candidate, identify attacker-controlled input, propagation, sanitizer or guard checks, sink, and reachable preconditions. ",
            "Reject or downgrade findings when the provided code does not support a concrete path."
        ),
    },
    WorkflowStep {
        id: "report",
        title: "Report Generation",
        prompt: concat!(
            "Perform a final self-review against the evidence above, then output the finished report as structured JSON that matches the supplied schema. ",
            "Create exactly one finding object for every scanner finding listed in Report ID Map, preserving the assigned MAKINA id order even when multiple findings share a CWE. ",
            "Each object id must be exactly MAKINA-001, MAKINA-002, and so on. ",
            "Populate the title, summary, vulnerability_details, impact, proof_of_concept, remediation, verification_notes, and confidence fields with concise report-ready prose. ",
            "Do not put Markdown headings inside field values; Makina will render the final headings. ",
            "The Proof of Concept section must be a minimal reproduction sketch or safe test input, not a weaponized exploit. ",
            "If a finding is not externally exploitable from the submitted code alone, still output its assigned MAKINA object and say that caller/source evidence is missing in verification_notes."
        ),
    },
];

#[derive(Debug, Deserialize)]
struct StructuredAuditReport {
    findings: Vec<StructuredAuditFinding>,
}

#[derive(Debug, Deserialize)]
struct StructuredAuditFinding {
    id: String,
    title: String,
    summary: String,
    vulnerability_details: String,
    impact: String,
    proof_of_concept: String,
    remediation: String,
    verification_notes: String,
    confidence: String,
}

#[derive(Serialize)]
struct FindingSummary<'a> {
    id: &'a str,
    rule_id: &'a str,
    severity: &'a crate::api::models::Severity,
    cwe: &'a Option<String>,
    source: &'a str,
    message: &'a str,
    line_start: u32,
    line_end: u32,
    confidence: f32,
    is_uncertain: bool,
    code_snippet: String,
}

pub async fn run(
    Extension(req_id): Extension<RequestId>,
    Json(req): Json<AuditRunRequest>,
) -> impl IntoResponse {
    let client = MlClient::new();
    let mut results = Vec::with_capacity(WORKFLOW.len());

    for step in WORKFLOW {
        let started_at = Instant::now();
        let prompt = build_step_prompt(&req, step, &results);
        let step_req = AuditStepRunRequest {
            provider: req.provider.clone(),
            api_key: req.api_key.clone(),
            model: req.model.clone(),
            max_output_tokens: output_token_budget(step, req.max_output_tokens),
            system_prompt: SYSTEM_PROMPT.to_string(),
            prompt,
            response_schema: response_schema_for_step(step),
        };

        match client.audit_step(&req_id.0, &step_req).await {
            Ok(response) => {
                let output = if step.id == "report" {
                    report_output_to_markdown(&req, &response.output)
                } else {
                    response.output
                };
                results.push(AuditWorkflowResult {
                    id: step.id.to_string(),
                    title: step.title.to_string(),
                    status: AuditStepStatus::Complete,
                    output,
                    error: None,
                    duration_ms: started_at.elapsed().as_millis() as u64,
                });
            }
            Err(err) => {
                results.push(AuditWorkflowResult {
                    id: step.id.to_string(),
                    title: step.title.to_string(),
                    status: AuditStepStatus::Error,
                    output: String::new(),
                    error: Some(sanitize_provider_error(&err.to_string(), &req.api_key)),
                    duration_ms: started_at.elapsed().as_millis() as u64,
                });
                break;
            }
        }
    }

    let report_markdown = extract_report_markdown(&req, &results);
    let report_sections = report_sections_from_markdown(&req, &report_markdown);
    Json(AuditRunResponse {
        results,
        report_markdown,
        report_sections,
    })
}

fn response_schema_for_step(step: &WorkflowStep) -> Option<Value> {
    if step.id == "report" {
        Some(audit_report_schema())
    } else {
        None
    }
}

fn audit_report_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "findings": {
                "type": "array",
                "description": "One report object per scanner finding, in MAKINA identifier order.",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "The assigned report id, for example MAKINA-001."
                        },
                        "title": {
                            "type": "string",
                            "description": "Short report title, preferably including CWE and affected component."
                        },
                        "summary": {
                            "type": "string",
                            "description": "A concise finding summary. No Markdown heading."
                        },
                        "vulnerability_details": {
                            "type": "string",
                            "description": "Evidence, source-to-sink path, guards, sanitizers, and limits. No Markdown heading."
                        },
                        "impact": {
                            "type": "string",
                            "description": "Security impact, constrained to what the submitted code supports. No Markdown heading."
                        },
                        "proof_of_concept": {
                            "type": "string",
                            "description": "Minimal non-destructive reproduction sketch or safe test input. No weaponized exploit and no Markdown heading."
                        },
                        "remediation": {
                            "type": "string",
                            "description": "Concrete remediation guidance. No Markdown heading."
                        },
                        "verification_notes": {
                            "type": "string",
                            "description": "Missing evidence and validation steps before external exploitability is claimed. No Markdown heading."
                        },
                        "confidence": {
                            "type": "string",
                            "description": "Confidence statement separating scanner evidence from confirmed exploitability. No Markdown heading."
                        }
                    },
                    "required": [
                        "id",
                        "title",
                        "summary",
                        "vulnerability_details",
                        "impact",
                        "proof_of_concept",
                        "remediation",
                        "verification_notes",
                        "confidence"
                    ]
                }
            }
        },
        "required": ["findings"]
    })
}

fn build_step_prompt(
    req: &AuditRunRequest,
    step: &WorkflowStep,
    previous_results: &[AuditWorkflowResult],
) -> String {
    let previous = if previous_results.is_empty() {
        "No previous audit steps.".to_string()
    } else {
        previous_results
            .iter()
            .map(|result| {
                format!(
                    "## {}\n{}",
                    result.title,
                    if result.output.is_empty() {
                        result.error.as_deref().unwrap_or("(no output)")
                    } else {
                        &result.output
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    [
        "# Audit Context".to_string(),
        build_audit_context(req),
        String::new(),
        "# Previous Step Results".to_string(),
        previous,
        String::new(),
        "# Current Step".to_string(),
        format!("Title: {}", step.title),
        step.prompt.to_string(),
    ]
    .join("\n")
}

fn output_token_budget(step: &WorkflowStep, requested: u32) -> u32 {
    if step.id == "report" {
        requested.max(4000)
    } else {
        requested
    }
}

fn build_audit_context(req: &AuditRunRequest) -> String {
    let findings: Vec<FindingSummary<'_>> = req
        .findings
        .iter()
        .take(FINDING_LIMIT)
        .map(summarize_finding)
        .collect();
    let omitted = req.findings.len().saturating_sub(findings.len());
    let findings_json = serde_json::to_string_pretty(&findings).unwrap_or_else(|_| "[]".into());

    [
        format!("Scan ID: {}", req.scan_id.as_deref().unwrap_or("unknown")),
        format!("Language: {}", language_hint(&req.language)),
        format!(
            "Findings: {}{}",
            req.findings.len(),
            if omitted > 0 {
                format!(" ({omitted} omitted from prompt)")
            } else {
                String::new()
            }
        ),
        String::new(),
        "Report ID Map:".to_string(),
        build_report_id_map(&req.findings),
        String::new(),
        "Findings JSON:".to_string(),
        "```json".to_string(),
        findings_json,
        "```".to_string(),
        String::new(),
        "Code:".to_string(),
        "```".to_string(),
        truncate_text(&req.code, CODE_CHAR_LIMIT),
        "```".to_string(),
    ]
    .join("\n")
}

fn build_report_id_map(findings: &[Finding]) -> String {
    findings
        .iter()
        .take(FINDING_LIMIT)
        .enumerate()
        .map(|(idx, finding)| {
            format!(
                "- {} => finding_id={} rule_id={} cwe={} line={}",
                report_id(idx),
                finding.id,
                finding.rule_id,
                finding.cwe.as_deref().unwrap_or("unknown"),
                finding.line_start
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn summarize_finding(finding: &Finding) -> FindingSummary<'_> {
    FindingSummary {
        id: &finding.id,
        rule_id: &finding.rule_id,
        severity: &finding.severity,
        cwe: &finding.cwe,
        source: &finding.source,
        message: &finding.message,
        line_start: finding.line_start,
        line_end: finding.line_end,
        confidence: finding.confidence,
        is_uncertain: finding.is_uncertain,
        code_snippet: truncate_text(&finding.code_snippet, 1200),
    }
}

fn truncate_text(value: &str, limit: usize) -> String {
    let count = value.chars().count();
    if count <= limit {
        return value.to_string();
    }
    let truncated: String = value.chars().take(limit).collect();
    format!(
        "{truncated}\n\n[truncated {} characters]",
        count.saturating_sub(limit)
    )
}

fn sanitize_provider_error(message: &str, api_key: &str) -> String {
    if api_key.is_empty() {
        return message.to_string();
    }
    message.replace(api_key, "[redacted]")
}

fn extract_report_markdown(req: &AuditRunRequest, results: &[AuditWorkflowResult]) -> String {
    if results
        .iter()
        .any(|result| matches!(&result.status, AuditStepStatus::Error))
    {
        return String::new();
    }
    let report = results
        .iter()
        .find(|result| result.id == "report" && matches!(&result.status, AuditStepStatus::Complete))
        .map(|result| result.output.trim())
        .unwrap_or_default();
    report_output_to_markdown(req, report)
}

fn report_output_to_markdown(req: &AuditRunRequest, output: &str) -> String {
    if let Some(sections) = structured_report_to_sections(req, output) {
        return render_report_sections(&sections);
    }
    let normalized = normalize_report_markdown(output);
    if report_is_complete(&normalized, req.findings.len().min(FINDING_LIMIT)) {
        normalized
    } else {
        build_fallback_report(req)
    }
}

fn structured_report_to_sections(
    req: &AuditRunRequest,
    output: &str,
) -> Option<Vec<AuditReportSection>> {
    let parsed: StructuredAuditReport = serde_json::from_str(output.trim()).ok()?;
    let expected_count = req.findings.len().min(FINDING_LIMIT);
    if expected_count == 0 {
        return None;
    }

    let mut sections = Vec::with_capacity(expected_count);
    for idx in 0..expected_count {
        let id = report_id(idx);
        let finding = parsed
            .findings
            .iter()
            .find(|candidate| candidate.id == id)?;
        sections.push(AuditReportSection {
            id,
            finding_id: req.findings.get(idx).map(|finding| finding.id.clone()),
            title: clean_report_text(&finding.title),
            summary: clean_report_text(&finding.summary),
            vulnerability_details: clean_report_text(&finding.vulnerability_details),
            impact: clean_report_text(&finding.impact),
            proof_of_concept: clean_report_text(&finding.proof_of_concept),
            remediation: clean_report_text(&finding.remediation),
            verification_notes: clean_report_text(&finding.verification_notes),
            confidence: clean_report_text(&finding.confidence),
        });
    }
    Some(sections)
}

fn render_report_sections(sections: &[AuditReportSection]) -> String {
    sections
        .iter()
        .map(render_report_section)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn render_report_section(section: &AuditReportSection) -> String {
    [
        format!("# {}: {}", section.id, clean_report_text(&section.title)),
        String::new(),
        "## Summary".to_string(),
        clean_report_text_or(&section.summary, "No summary was generated."),
        String::new(),
        "## Vulnerability Details".to_string(),
        clean_report_text_or(
            &section.vulnerability_details,
            "The provider did not generate vulnerability details.",
        ),
        String::new(),
        "## Impact".to_string(),
        clean_report_text_or(
            &section.impact,
            "Impact was not established from the submitted code.",
        ),
        String::new(),
        "## Proof of Concept".to_string(),
        clean_report_text_or(
            &section.proof_of_concept,
            "No safe proof-of-concept sketch was generated.",
        ),
        String::new(),
        "## Remediation".to_string(),
        clean_report_text_or(
            &section.remediation,
            "No remediation guidance was generated.",
        ),
        String::new(),
        "## Verification Notes".to_string(),
        clean_report_text_or(
            &section.verification_notes,
            "No verification notes were generated.",
        ),
        String::new(),
        "## Confidence".to_string(),
        clean_report_text_or(
            &section.confidence,
            "No confidence statement was generated.",
        ),
    ]
    .join("\n")
}

fn report_sections_from_markdown(req: &AuditRunRequest, markdown: &str) -> Vec<AuditReportSection> {
    let source = markdown.trim();
    if source.is_empty() {
        return Vec::new();
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut headings = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some((id, title)) = parse_makina_heading(line) {
            headings.push((line_idx, id, title));
        }
    }

    headings
        .iter()
        .enumerate()
        .map(|(idx, (line_idx, id, title))| {
            let end = headings
                .get(idx + 1)
                .map(|(next, _, _)| *next)
                .unwrap_or(lines.len());
            let body = lines[line_idx + 1..end].join("\n");
            let fields = parse_markdown_report_fields(&body);
            AuditReportSection {
                id: id.clone(),
                finding_id: finding_id_for_report_id(req, id),
                title: title.clone(),
                summary: fields.summary,
                vulnerability_details: fields.vulnerability_details,
                impact: fields.impact,
                proof_of_concept: fields.proof_of_concept,
                remediation: fields.remediation,
                verification_notes: fields.verification_notes,
                confidence: fields.confidence,
            }
        })
        .collect()
}

#[derive(Default)]
struct ReportFields {
    summary: String,
    vulnerability_details: String,
    impact: String,
    proof_of_concept: String,
    remediation: String,
    verification_notes: String,
    confidence: String,
}

fn parse_markdown_report_fields(body: &str) -> ReportFields {
    let mut fields = ReportFields::default();
    let mut current: Option<&str> = None;
    let mut buffer = String::new();

    for line in body.lines() {
        if let Some(section) = parse_report_subheading(line) {
            flush_report_field(&mut fields, current, &buffer);
            current = Some(section);
            buffer.clear();
        } else if current.is_some() {
            if !buffer.is_empty() {
                buffer.push('\n');
            }
            buffer.push_str(line);
        }
    }
    flush_report_field(&mut fields, current, &buffer);
    fields
}

fn parse_report_subheading(line: &str) -> Option<&'static str> {
    match line.trim() {
        "## Summary" => Some("summary"),
        "## Vulnerability Details" => Some("vulnerability_details"),
        "## Impact" => Some("impact"),
        "## Proof of Concept" => Some("proof_of_concept"),
        "## Remediation" => Some("remediation"),
        "## Verification Notes" => Some("verification_notes"),
        "## Confidence" => Some("confidence"),
        _ => None,
    }
}

fn flush_report_field(fields: &mut ReportFields, current: Option<&str>, buffer: &str) {
    let value = clean_report_text(buffer);
    match current {
        Some("summary") => fields.summary = value,
        Some("vulnerability_details") => fields.vulnerability_details = value,
        Some("impact") => fields.impact = value,
        Some("proof_of_concept") => fields.proof_of_concept = value,
        Some("remediation") => fields.remediation = value,
        Some("verification_notes") => fields.verification_notes = value,
        Some("confidence") => fields.confidence = value,
        _ => {}
    }
}

fn parse_makina_heading(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("# MAKINA-")?;
    let (number, title) = rest.split_once(':')?;
    if number.len() != 3 || !number.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some((
        format!("MAKINA-{number}"),
        clean_report_text_or(title, "Audit Report"),
    ))
}

fn finding_id_for_report_id(req: &AuditRunRequest, report_id: &str) -> Option<String> {
    let suffix = report_id.strip_prefix("MAKINA-")?;
    let idx = suffix.parse::<usize>().ok()?.checked_sub(1)?;
    req.findings.get(idx).map(|finding| finding.id.clone())
}

fn clean_report_text(value: &str) -> String {
    value.trim().to_string()
}

fn clean_report_text_or(value: &str, fallback: &str) -> String {
    let cleaned = clean_report_text(value);
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn normalize_report_markdown(markdown: &str) -> String {
    let trimmed = markdown.trim();
    if trimmed.is_empty() || trimmed == "(no text output)" {
        return String::new();
    }
    if has_makina_report_heading(trimmed) {
        return trimmed.to_string();
    }
    format!("# MAKINA-001: Audit Report\n\n{trimmed}")
}

fn has_makina_report_heading(markdown: &str) -> bool {
    markdown.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix("# MAKINA-") else {
            return false;
        };
        let mut chars = rest.chars();
        matches!(
            (chars.next(), chars.next(), chars.next()),
            (Some(a), Some(b), Some(c)) if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit()
        )
    })
}

fn report_is_complete(markdown: &str, expected_count: usize) -> bool {
    if expected_count == 0 {
        return !markdown.trim().is_empty();
    }
    (0..expected_count).all(|idx| markdown.contains(&format!("# {}:", report_id(idx))))
}

fn build_fallback_report(req: &AuditRunRequest) -> String {
    if req.findings.is_empty() {
        return [
            "# MAKINA-001: No Scanner Findings".to_string(),
            String::new(),
            "## Summary".to_string(),
            "The submitted scan did not include findings to audit.".to_string(),
            String::new(),
            "## Verification Notes".to_string(),
            "Run Scan again or submit findings before running Audit.".to_string(),
        ]
        .join("\n");
    }

    req.findings
        .iter()
        .take(FINDING_LIMIT)
        .enumerate()
        .map(|(idx, finding)| build_fallback_report_section(idx, finding))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn build_fallback_report_section(idx: usize, finding: &Finding) -> String {
    let cwe = finding.cwe.as_deref().unwrap_or("Unknown CWE");
    let title = title_from_finding(finding);
    [
        format!("# {}: {}", report_id(idx), title),
        String::new(),
        "## Summary".to_string(),
        format!(
            "{} reported `{}` at line {} with {} severity and {:.2} confidence.",
            finding.source,
            finding.rule_id,
            finding.line_start,
            severity_label(&finding.severity),
            finding.confidence
        ),
        String::new(),
        "## Vulnerability Details".to_string(),
        format!(
            "- CWE: {cwe}\n- Finding ID: `{}`\n- Lines: {}-{}\n- Scanner message: {}",
            finding.id, finding.line_start, finding.line_end, finding.message
        ),
        String::new(),
        "## Impact".to_string(),
        "Potential impact depends on whether an attacker can reach the reported source-to-sink path in the surrounding application.".to_string(),
        String::new(),
        "## Proof of Concept".to_string(),
        "The scanner evidence is the minimal reproduction context available from the submitted code:".to_string(),
        String::new(),
        "```".to_string(),
        truncate_text(&finding.code_snippet, 1600),
        "```".to_string(),
        String::new(),
        "## Remediation".to_string(),
        remediation_for_finding(finding),
        String::new(),
        "## Verification Notes".to_string(),
        "Confirm the caller, attacker-controlled inputs, guards/sanitizers, and runtime reachability before treating this as an externally exploitable vulnerability.".to_string(),
        String::new(),
        "## Confidence".to_string(),
        if finding.is_uncertain {
            "Needs human review; scanner confidence is in the uncertain band.".to_string()
        } else {
            "Scanner evidence is strong enough to keep this item in the audit report, but exploitability still depends on the missing caller/source context.".to_string()
        },
    ]
    .join("\n")
}

fn report_id(idx: usize) -> String {
    format!("MAKINA-{:03}", idx + 1)
}

fn title_from_finding(finding: &Finding) -> String {
    if let Some(cwe) = finding.cwe.as_deref() {
        format!(
            "{cwe} {}",
            finding
                .message
                .split(" (")
                .next()
                .unwrap_or(&finding.message)
        )
    } else {
        finding
            .message
            .split(" (")
            .next()
            .unwrap_or(&finding.message)
            .to_string()
    }
}

fn severity_label(severity: &crate::api::models::Severity) -> &'static str {
    match severity {
        crate::api::models::Severity::Critical => "critical",
        crate::api::models::Severity::High => "high",
        crate::api::models::Severity::Medium => "medium",
        crate::api::models::Severity::Low => "low",
    }
}

fn remediation_for_finding(finding: &Finding) -> String {
    let cwe = finding.cwe.as_deref().unwrap_or_default();
    if cwe == "CWE-89" {
        "Use parameterized SQL queries or a query builder that binds values separately from SQL syntax.".to_string()
    } else if cwe == "CWE-78" {
        "Avoid shell invocation for untrusted data. Use an argument-vector API and validate or allowlist command arguments.".to_string()
    } else if cwe == "CWE-502" {
        "Do not deserialize untrusted bytes with unsafe object deserializers. Use a safe data format such as JSON and validate the schema.".to_string()
    } else if cwe == "CWE-94" || cwe == "CWE-95" {
        "Avoid dynamic code evaluation. Replace it with explicit parsing, allowlisted operations, or a constrained interpreter.".to_string()
    } else if cwe == "CWE-22" {
        "Normalize paths, reject traversal segments, and enforce that resolved paths remain under the intended base directory.".to_string()
    } else {
        "Apply a code-level fix that removes the unsafe source-to-sink pattern, then add regression tests for both benign and malicious inputs.".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_provider_error_redacts_api_key() {
        let out = sanitize_provider_error("bad key sk-test-value", "sk-test-value");
        assert_eq!(out, "bad key [redacted]");
    }

    #[test]
    fn truncate_text_reports_omitted_character_count() {
        let out = truncate_text("abcdef", 3);
        assert_eq!(out, "abc\n\n[truncated 3 characters]");
    }

    #[test]
    fn normalize_report_markdown_keeps_makina_heading() {
        let out = normalize_report_markdown("# MAKINA-001: SQL Injection\n\n## Summary\n...");
        assert_eq!(out, "# MAKINA-001: SQL Injection\n\n## Summary\n...");
    }

    #[test]
    fn normalize_report_markdown_adds_makina_heading_when_missing() {
        let out = normalize_report_markdown("## Summary\nEvidence.");
        assert!(out.starts_with("# MAKINA-001: Audit Report\n\n## Summary"));
    }

    #[test]
    fn report_is_complete_requires_every_expected_finding_heading() {
        let report = "# MAKINA-001: A\n\n# MAKINA-002: B";
        assert!(report_is_complete(report, 2));
        assert!(!report_is_complete(report, 3));
    }

    #[test]
    fn structured_report_json_renders_canonical_markdown_sections() {
        let req = AuditRunRequest {
            provider: crate::api::models::AuditProvider::Openai,
            api_key: "sk-test".into(),
            model: "model".into(),
            max_output_tokens: 4000,
            scan_id: None,
            code: "cursor.execute(query)".into(),
            language: crate::api::models::Language::Python,
            findings: vec![Finding {
                id: "finding-1".into(),
                rule_id: "taint-python-sqli".into(),
                message: "SQL Injection".into(),
                severity: crate::api::models::Severity::Critical,
                line_start: 10,
                line_end: 10,
                code_snippet: "cursor.execute(query)".into(),
                confidence: 0.85,
                is_uncertain: false,
                cwe: Some("CWE-89".into()),
                source: "semgrep".into(),
            }],
        };
        let output = r#"{
            "findings": [
                {
                    "id": "MAKINA-001",
                    "title": "CWE-89 SQL Injection",
                    "summary": "Confirmed unsafe SQL construction.",
                    "vulnerability_details": "User input reaches `cursor.execute` without parameter binding.",
                    "impact": "A reachable caller could alter SQL syntax.",
                    "proof_of_concept": "GET /user?name=alice'",
                    "remediation": "Use parameterized queries.",
                    "verification_notes": "Confirm the HTTP caller and auth boundary.",
                    "confidence": "High for the sink pattern; exploitability depends on reachability."
                }
            ]
        }"#;

        let markdown = report_output_to_markdown(&req, output);

        assert!(markdown.starts_with("# MAKINA-001: CWE-89 SQL Injection"));
        assert!(markdown.contains("## Summary\nConfirmed unsafe SQL construction."));
        assert!(markdown.contains("## Vulnerability Details\nUser input reaches `cursor.execute`"));
        assert!(markdown.contains("## Confidence\nHigh for the sink pattern"));
        assert!(!markdown.contains("\"findings\""));
    }

    #[test]
    fn rendered_report_markdown_round_trips_to_structured_sections() {
        let req = AuditRunRequest {
            provider: crate::api::models::AuditProvider::Openai,
            api_key: "sk-test".into(),
            model: "model".into(),
            max_output_tokens: 4000,
            scan_id: None,
            code: "cursor.execute(query)".into(),
            language: crate::api::models::Language::Python,
            findings: vec![Finding {
                id: "finding-1".into(),
                rule_id: "taint-python-sqli".into(),
                message: "SQL Injection".into(),
                severity: crate::api::models::Severity::Critical,
                line_start: 10,
                line_end: 10,
                code_snippet: "cursor.execute(query)".into(),
                confidence: 0.85,
                is_uncertain: false,
                cwe: Some("CWE-89".into()),
                source: "semgrep".into(),
            }],
        };
        let markdown = "# MAKINA-001: CWE-89 SQL Injection\n\n## Summary\nConfirmed.\n\n## Vulnerability Details\nSource reaches sink.\n\n## Impact\nData exposure.\n\n## Proof of Concept\nSafe input.\n\n## Remediation\nBind parameters.\n\n## Verification Notes\nConfirm route.\n\n## Confidence\nHigh.";

        let sections = report_sections_from_markdown(&req, markdown);

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].id, "MAKINA-001");
        assert_eq!(sections[0].finding_id.as_deref(), Some("finding-1"));
        assert_eq!(sections[0].summary, "Confirmed.");
        assert_eq!(sections[0].vulnerability_details, "Source reaches sink.");
        assert_eq!(sections[0].proof_of_concept, "Safe input.");
    }

    #[test]
    fn structured_report_json_requires_every_expected_makina_id() {
        let req = AuditRunRequest {
            provider: crate::api::models::AuditProvider::Openai,
            api_key: "sk-test".into(),
            model: "model".into(),
            max_output_tokens: 4000,
            scan_id: None,
            code: "x".into(),
            language: crate::api::models::Language::Python,
            findings: vec![
                Finding {
                    id: "finding-1".into(),
                    rule_id: "rule-a".into(),
                    message: "A".into(),
                    severity: crate::api::models::Severity::High,
                    line_start: 1,
                    line_end: 1,
                    code_snippet: "a".into(),
                    confidence: 0.7,
                    is_uncertain: false,
                    cwe: Some("CWE-89".into()),
                    source: "semgrep".into(),
                },
                Finding {
                    id: "finding-2".into(),
                    rule_id: "rule-b".into(),
                    message: "B".into(),
                    severity: crate::api::models::Severity::High,
                    line_start: 2,
                    line_end: 2,
                    code_snippet: "b".into(),
                    confidence: 0.7,
                    is_uncertain: false,
                    cwe: Some("CWE-78".into()),
                    source: "semgrep".into(),
                },
            ],
        };
        let output = r#"{"findings":[{"id":"MAKINA-001","title":"A","summary":"A","vulnerability_details":"A","impact":"A","proof_of_concept":"A","remediation":"A","verification_notes":"A","confidence":"A"}]}"#;

        let markdown = report_output_to_markdown(&req, output);

        assert!(markdown.contains("# MAKINA-001: CWE-89 A"));
        assert!(markdown.contains("# MAKINA-002: CWE-78 B"));
    }

    #[test]
    fn no_text_output_is_not_treated_as_report() {
        assert_eq!(normalize_report_markdown("(no text output)"), "");
    }

    #[test]
    fn extract_report_markdown_returns_empty_on_provider_error() {
        let req = AuditRunRequest {
            provider: crate::api::models::AuditProvider::Openai,
            api_key: "sk-test".into(),
            model: "model".into(),
            max_output_tokens: 4000,
            scan_id: None,
            code: "x".into(),
            language: crate::api::models::Language::Python,
            findings: vec![],
        };
        let results = vec![AuditWorkflowResult {
            id: "triage".into(),
            title: "Evidence Triage".into(),
            status: AuditStepStatus::Error,
            output: String::new(),
            error: Some("failed".into()),
            duration_ms: 1,
        }];
        assert_eq!(extract_report_markdown(&req, &results), "");
    }
}
