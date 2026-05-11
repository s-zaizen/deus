import { PUBLIC_API_URL } from '$env/static/public';
import type { AuditCase, AuditProvider, AuditStepResult, Finding } from '$lib/types';

export const DEFAULT_OPENAI_MODEL = 'gpt-5.5';
export const DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-4-20250514';
export const DEFAULT_MAX_OUTPUT_TOKENS = 4000;

const BASE = PUBLIC_API_URL || 'http://localhost:7373';

export interface AuditRunOptions {
	provider: AuditProvider;
	apiKey: string;
	model: string;
	maxOutputTokens: number;
	auditCase: AuditCase;
	findings?: Finding[];
}

interface AuditRunResultWire {
	id: string;
	title: string;
	status: 'complete' | 'error';
	output: string;
	error: string | null;
	duration_ms: number;
}

interface AuditRunResponseWire {
	results?: AuditRunResultWire[];
	report_markdown?: string;
}

function toStepResult(result: AuditRunResultWire): AuditStepResult {
	return {
		id: result.id,
		title: result.title,
		status: result.status,
		output: result.output,
		error: result.error,
		durationMs: result.duration_ms
	};
}

export async function runAuditWorkflow(options: AuditRunOptions): Promise<{ results: AuditStepResult[]; reportMarkdown: string }> {
	const res = await fetch(`${BASE}/api/audit/run`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			provider: options.provider,
			api_key: options.apiKey,
			model: options.model,
			max_output_tokens: options.maxOutputTokens,
			scan_id: options.auditCase.scanId,
			code: options.auditCase.code,
			language: options.auditCase.language,
			findings: options.findings ?? options.auditCase.findings
		})
	});

	if (!res.ok) {
		let detail = `Audit workflow failed: ${res.status}`;
		const bodyText = await res.text();
		if (bodyText) {
			try {
				const body = JSON.parse(bodyText);
				detail = body?.detail || body?.error || detail;
			} catch {
				detail = bodyText;
			}
		}
		throw new Error(detail);
	}

	const body = (await res.json()) as AuditRunResponseWire;
	return {
		results: (body.results ?? []).map(toStepResult),
		reportMarkdown: body.report_markdown ?? ''
	};
}
