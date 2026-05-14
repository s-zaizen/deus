import { describe, expect, it } from 'vitest';
import {
	mapAuditReportSections,
	reportIdForIndex,
	reportSectionFromWire,
	splitReportMarkdown
} from './auditReport';

describe('audit report section helpers', () => {
	it('formats stable MAKINA IDs', () => {
		expect(reportIdForIndex(0)).toBe('MAKINA-001');
		expect(reportIdForIndex(11)).toBe('MAKINA-012');
	});

	it('splits one markdown report into per-finding sections', () => {
		const sections = splitReportMarkdown(`# MAKINA-001: SQL Injection

## Summary
First.

# MAKINA-002: Command Injection

## Summary
Second.`);

		expect(sections).toEqual([
			{ id: 'MAKINA-001', title: 'SQL Injection', source: '## Summary\nFirst.' },
			{ id: 'MAKINA-002', title: 'Command Injection', source: '## Summary\nSecond.' }
		]);
	});

	it('maps report sections back to audited finding IDs', () => {
		const sections = mapAuditReportSections(
			'# MAKINA-001: One\n\nBody\n\n# MAKINA-002: Two\n\nBody',
			['finding-a'],
			['fallback-a', 'fallback-b']
		);

		expect(sections.map((section) => section.findingId)).toEqual(['finding-a', 'fallback-b']);
	});

	it('normalizes structured report sections from backend wire format', () => {
		const section = reportSectionFromWire({
			id: 'MAKINA-001',
			finding_id: 'finding-a',
			title: 'CWE-89 SQL Injection',
			summary: 'Confirmed.',
			vulnerability_details: 'Source reaches sink.',
			impact: 'Data exposure.',
			proof_of_concept: 'GET /user?name=alice',
			remediation: 'Bind parameters.',
			verification_notes: 'Confirm route.',
			confidence: 'High.'
		});

		expect(section.findingId).toBe('finding-a');
		expect(section.vulnerabilityDetails).toBe('Source reaches sink.');
		expect(section.source).toContain('## Summary\nConfirmed.');
		expect(section.source).toContain('## Vulnerability Details\nSource reaches sink.');
	});
});
