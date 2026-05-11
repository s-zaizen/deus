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
use serde::Serialize;

use crate::api::models::{
    AuditRunRequest, AuditRunResponse, AuditStepRunRequest, AuditStepStatus, AuditWorkflowResult,
    Finding,
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
    "When discussing proof of concept material, keep it minimal, non-destructive, and scoped to reproduction evidence."
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
            "Perform a final self-review against the evidence above, then output only the finished Markdown report. ",
            "Create exactly one top-level report section for every scanner finding listed in Report ID Map, preserving the assigned MAKINA id order even when multiple findings share a CWE. ",
            "Each top-level heading must be exactly '# MAKINA-001: <short title>', '# MAKINA-002: <short title>', and so on. ",
            "Use only these second-level sections when evidence supports them: Summary, Vulnerability Details, Impact, Proof of Concept, Remediation, Verification Notes, Confidence. ",
            "The Proof of Concept section must be a minimal reproduction sketch or safe test input, not a weaponized exploit. ",
            "If a finding is not externally exploitable from the submitted code alone, still output its assigned MAKINA section and say that caller/source evidence is missing in Verification Notes."
        ),
    },
];

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
        };

        match client.audit_step(&req_id.0, &step_req).await {
            Ok(response) => results.push(AuditWorkflowResult {
                id: step.id.to_string(),
                title: step.title.to_string(),
                status: AuditStepStatus::Complete,
                output: response.output,
                error: None,
                duration_ms: started_at.elapsed().as_millis() as u64,
            }),
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
    Json(AuditRunResponse {
        results,
        report_markdown,
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
    let normalized = normalize_report_markdown(report);
    if report_is_complete(&normalized, req.findings.len().min(FINDING_LIMIT)) {
        normalized
    } else {
        build_fallback_report(req)
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
