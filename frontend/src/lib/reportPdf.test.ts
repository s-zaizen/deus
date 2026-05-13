import { describe, expect, it } from 'vitest';
import { buildAuditPdfDefinition } from './reportPdf';
import type { AuditCase } from './types';
import type { TVirtualFileSystem } from 'pdfmake/interfaces';

const auditCase: AuditCase = {
	id: 'audit-1',
	scanId: 'scan-1234567890',
	code: 'cursor.execute(query)',
	language: 'python',
	createdAt: '2026-05-13T00:00:00.000Z',
	findings: [
		{
			id: 'finding-1',
			rule_id: 'taint-python-sqli',
			message: 'SQL Injection',
			severity: 'critical',
			line_start: 10,
			line_end: 12,
			code_snippet: 'cursor.execute(query)',
			confidence: 0.85,
			is_uncertain: false,
			cwe: 'CWE-89',
			source: 'semgrep'
		}
	]
};

const pdfPageSize = { width: 595.28, height: 841.89, orientation: 'portrait' as const };

function pageHeaderFor(doc: ReturnType<typeof buildAuditPdfDefinition>) {
	if (typeof doc.header !== 'function') return null;
	return doc.header(2, 10, pdfPageSize);
}

function coverPageFor(doc: ReturnType<typeof buildAuditPdfDefinition>) {
	return Array.isArray(doc.content) ? doc.content[0] : null;
}

function coverBackgroundFor(doc: ReturnType<typeof buildAuditPdfDefinition>) {
	if (typeof doc.background !== 'function') return null;
	return doc.background(1, pdfPageSize);
}

function firstFindingPageFor(doc: ReturnType<typeof buildAuditPdfDefinition>) {
	return Array.isArray(doc.content) ? doc.content[2] : null;
}

describe('buildAuditPdfDefinition', () => {
	it('creates a Makina styled PDF definition from audit markdown', () => {
		const doc = buildAuditPdfDefinition({
			auditCase,
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: `# MAKINA-001: SQL Injection in user lookup

## Summary
Confirmed SQL injection.

## Remediation
Use parameterized queries.`
		});

		expect(doc.pageSize).toBe('A4');
		expect(JSON.stringify(doc.content)).toContain('MAKINA-001');
		expect(JSON.stringify(coverPageFor(doc))).toContain('1 Finding Analyzed');
		expect(JSON.stringify(doc.content)).toContain('SQL Injection in user lookup');
		expect(JSON.stringify(doc.content)).toContain('CWE-89');
		expect(JSON.stringify(doc.content)).toContain('M 108 178 Q 92 202 72 214');
		expect(JSON.stringify(doc.content)).toContain(`scan-${String.fromCharCode(8203)}1234567890`);
	});

	it('extends the existing cover colors without a separate purple side panel', () => {
		const doc = buildAuditPdfDefinition({
			auditCase,
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: '# MAKINA-001: SQL Injection\n\n## Summary\nConfirmed.'
		});
		const backgroundJson = JSON.stringify(coverBackgroundFor(doc));

		expect(backgroundJson).toContain('"color":"#070b14"');
		expect(backgroundJson).toContain('"color":"#0d1220"');
		expect(backgroundJson).not.toContain('#14112b');
	});

	it('uses a readable finding header with a severity side bar', () => {
		const doc = buildAuditPdfDefinition({
			auditCase,
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: '# MAKINA-001: SQL Injection\n\n## Summary\nConfirmed.'
		});
		const findingHeaderJson = JSON.stringify(firstFindingPageFor(doc));

		expect(findingHeaderJson).toContain('"widths":[6,"*"]');
		expect(findingHeaderJson).toContain('"fillColor":"#dc2626"');
		expect(findingHeaderJson).toContain('"fillColor":"#ffffff"');
		expect(findingHeaderJson).toContain('"style":"findingTitle"');
		expect(findingHeaderJson).not.toContain('"style":"findingTitleOnColor"');
	});

	it('uses structured report fields for richer PDF finding bodies', () => {
		const doc = buildAuditPdfDefinition({
			auditCase,
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: '',
			reportSections: [
				{
					id: 'MAKINA-001',
					findingId: 'finding-1',
					title: 'CWE-89 SQL Injection',
					source: '',
					summary: 'Confirmed SQL injection.',
					vulnerabilityDetails: 'User input reaches `cursor.execute`.',
					impact: 'Unauthorized data access.',
					proofOfConcept: 'GET /user?name=alice',
					remediation: 'Use parameterized queries.',
					verificationNotes: 'Confirm route reachability.',
					confidence: 'High.'
				}
			]
		});
		const findingJson = JSON.stringify(doc.content);

		expect(findingJson).toContain('Vulnerability Details');
		expect(findingJson).toContain('Proof of Concept');
		expect(findingJson).toContain('structuredHeading');
		expect(findingJson).toContain('User input reaches');
	});

	it('uses a generic package title on the cover for audit-all reports', () => {
		const multiFindingCase: AuditCase = {
			...auditCase,
			scanId: 'audit-all-6b027fc5-87e6-45b4-afbb-f24c01b97944',
			findings: [
				auditCase.findings[0],
				{
					...auditCase.findings[0],
					id: 'finding-2',
					rule_id: 'taint-go-cmdi',
					message: 'Command Injection',
					severity: 'high',
					cwe: 'CWE-78',
					line_start: 26,
					line_end: 26
				}
			]
		};
		const doc = buildAuditPdfDefinition({
			auditCase: multiFindingCase,
			findingIds: ['finding-1', 'finding-2'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: `# MAKINA-001: CWE-89 [vulnerable-code/go/server.go] SQL Injection

## Summary
Confirmed.

# MAKINA-002: CWE-78 [vulnerable-code/go/server.go] Command Injection

## Summary
Confirmed.`
		});
		const coverJson = JSON.stringify(coverPageFor(doc));
		const contentJson = JSON.stringify(doc.content).replaceAll(String.fromCharCode(8203), '');

		expect(coverJson).toContain('2 Findings Analyzed');
		expect(coverJson).not.toContain('vulnerable-code/go/server.go');
		expect(coverJson).not.toContain('CWE-89');
		expect(contentJson).toContain('vulnerable-code/go/server.go');
		expect(contentJson).toContain('CWE-89');
	});

	it('keeps the page header aligned and compact for long scan ids', () => {
		const longScanId = 'audit-all-8fe052cc-e48b-4757-bcd2-b3b33e630963';
		const doc = buildAuditPdfDefinition({
			auditCase: { ...auditCase, scanId: longScanId },
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: '# MAKINA-001: SQL Injection\n\n## Summary\nConfirmed.'
		});
		const headerJson = JSON.stringify(pageHeaderFor(doc));
		const contentJson = JSON.stringify(doc.content).replaceAll(String.fromCharCode(8203), '');

		expect(headerJson).toContain('MAKINA LLM AUDIT');
		expect(headerJson).toContain('python / audit-all-8fe052cc');
		expect(headerJson).not.toContain(longScanId);
		expect(headerJson).toContain('"x2":507.28');
		expect(contentJson).toContain(longScanId);
	});

	it('is accepted by pdfmake', async () => {
		const [pdfMakeModule, vfsModule] = await Promise.all([
			import('pdfmake/build/pdfmake'),
			import('pdfmake/build/vfs_fonts')
		]);
		const pdfMake = ((pdfMakeModule as unknown as { default?: typeof pdfMakeModule }).default ??
			pdfMakeModule) as typeof pdfMakeModule;
		const vfs =
			(vfsModule as unknown as { default?: TVirtualFileSystem }).default ??
			(vfsModule as unknown as TVirtualFileSystem);

		pdfMake.addVirtualFileSystem(vfs);
		const doc = buildAuditPdfDefinition({
			auditCase,
			findingIds: ['finding-1'],
			generatedAt: new Date('2026-05-13T00:00:00.000Z'),
			reportMarkdown: '# MAKINA-001: SQL Injection\n\n## Summary\nConfirmed.'
		});
		const buffer = await pdfMake.createPdf(doc).getBuffer();

		expect(buffer.byteLength).toBeGreaterThan(1000);
	});
});
