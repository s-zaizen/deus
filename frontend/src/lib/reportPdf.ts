import type {
	Content,
	ContentTable,
	StyleDictionary,
	TableCell,
	TDocumentDefinitions,
	TVirtualFileSystem
} from 'pdfmake/interfaces';
import { mapAuditReportSections, type AuditReportSection } from '$lib/auditReport';
import { parseMarkdown, type BlockNode, type InlineNode } from '$lib/markdown';
import type { AuditCase, Finding, Severity } from '$lib/types';

const BRAND = {
	bg: '#070b14',
	bg2: '#0d1220',
	panel: '#121826',
	ink: '#101827',
	muted: '#667085',
	border: '#d7dce5',
	paper: '#ffffff',
	canvas: '#f3f5f9',
	violet: '#6d5df6',
	violetDark: '#2d245d',
	copper: '#b98252',
	teal: '#14b8a6',
	tealSoft: '#ccfbf1',
	ivory: '#f4f1e8'
};

const SEVERITY: Record<Severity, { color: string; soft: string; label: string }> = {
	critical: { color: '#dc2626', soft: '#fee2e2', label: 'Critical' },
	high: { color: '#ea580c', soft: '#ffedd5', label: 'High' },
	medium: { color: '#ca8a04', soft: '#fef3c7', label: 'Medium' },
	low: { color: '#2563eb', soft: '#dbeafe', label: 'Low' }
};

const MAKINA_EYE_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" rx="21" fill="#070b14"/>
  <circle cx="50" cy="51" r="42" fill="#4f46e5" opacity="0.12"/>
  <g transform="translate(4 4) scale(0.36)" fill="none" stroke-linecap="round" stroke-linejoin="round">
    <path d="M 64 100 Q 128 60 192 100" stroke="#d8c7aa" stroke-width="8"/>
    <path d="M 76 128 Q 128 84 180 128" stroke="#f4f1e8" stroke-width="10"/>
    <path d="M 76 128 Q 128 196 180 128" stroke="#d8c7aa" stroke-width="6"/>
    <path d="M 76 128 Q 128 196 180 128" stroke="#b98252" stroke-width="2" opacity="0.9"/>
    <path d="M 108 178 Q 92 202 72 214" stroke="#d8c7aa" stroke-width="7"/>
    <path d="M 128 184 Q 128 214 124 236" stroke="#d8c7aa" stroke-width="9"/>
    <path d="M 148 178 Q 164 202 184 214" stroke="#d8c7aa" stroke-width="7"/>
    <path d="M 108 178 Q 92 202 72 214" stroke="#b98252" stroke-width="2.4" opacity="0.82"/>
    <path d="M 128 184 Q 128 214 124 236" stroke="#b98252" stroke-width="3.2" opacity="0.82"/>
    <path d="M 148 178 Q 164 202 184 214" stroke="#b98252" stroke-width="2.4" opacity="0.82"/>
  </g>
  <circle cx="50.1" cy="49.4" r="3.9" fill="#14b8a6"/>
  <circle cx="51.4" cy="48.1" r="1.25" fill="#99f6e4"/>
</svg>`;

const SOFT_BREAK = String.fromCharCode(8203);

interface PdfTextFragment {
	text: string;
	bold?: boolean;
	color?: string;
	background?: string;
}

export interface DownloadAuditPdfOptions {
	auditCase: AuditCase;
	reportMarkdown: string;
	findingIds: string[];
	reportSections?: AuditReportSection[];
	generatedAt?: Date;
}

type PdfMakeModule = Pick<typeof import('pdfmake/build/pdfmake'), 'addVirtualFileSystem' | 'createPdf'>;

let pdfMakePromise: Promise<PdfMakeModule> | null = null;

async function loadPdfMake(): Promise<PdfMakeModule> {
	if (!pdfMakePromise) {
		pdfMakePromise = Promise.all([
			import('pdfmake/build/pdfmake'),
			import('pdfmake/build/vfs_fonts')
		]).then(([pdfMake, vfsModule]) => {
			const runtime = ((pdfMake as unknown as { default?: PdfMakeModule }).default ??
				pdfMake) as PdfMakeModule;
			const vfs =
				(vfsModule as unknown as { default?: TVirtualFileSystem }).default ??
				(vfsModule as unknown as TVirtualFileSystem);
			runtime.addVirtualFileSystem(vfs);
			return runtime;
		});
	}
	return pdfMakePromise;
}

export async function downloadAuditPdf(options: DownloadAuditPdfOptions): Promise<void> {
	const pdfMake = await loadPdfMake();
	const doc = buildAuditPdfDefinition(options);
	await pdfMake.createPdf(doc).download(filenameForAudit(options.auditCase, options.generatedAt ?? new Date()));
}

export function buildAuditPdfDefinition(options: DownloadAuditPdfOptions): TDocumentDefinitions {
	const generatedAt = options.generatedAt ?? new Date();
	const fallbackFindingIds = options.auditCase.findings.map((finding) => finding.id);
	const sections = options.reportSections?.length
		? options.reportSections
		: mapAuditReportSections(
				options.reportMarkdown,
				options.findingIds,
				fallbackFindingIds
			);
	const findingsById = new Map(options.auditCase.findings.map((finding) => [finding.id, finding]));
	const reportFindings = sections
		.map((section) => (section.findingId ? findingsById.get(section.findingId) : null))
		.filter((finding): finding is Finding => Boolean(finding));
	const scopedFindings = reportFindings.length > 0 ? reportFindings : options.auditCase.findings;

	return {
		pageSize: 'A4',
		pageMargins: [44, 58, 44, 58],
		info: {
			title: 'Makina LLM Audit Report',
			author: 'Makina',
			subject: 'Security audit report',
			keywords: 'Makina, security, audit, vulnerability'
		},
		compress: true,
		background: (currentPage, pageSize) => pageBackground(currentPage, pageSize.width, pageSize.height),
		header: (currentPage, _pageCount, pageSize) =>
			currentPage === 1 ? null : pageHeader(options.auditCase, pageSize.width),
		footer: (currentPage, pageCount) =>
			currentPage === 1 ? null : pageFooter(currentPage, pageCount),
		defaultStyle: {
			font: 'Roboto',
			fontSize: 10,
			lineHeight: 1.35,
			color: BRAND.ink
		},
		styles: styles(),
		content: [
			coverPage(options.auditCase, scopedFindings, sections, generatedAt),
			overviewPage(options.auditCase, scopedFindings, sections, generatedAt),
			...sections.flatMap((section, index) =>
				findingSection(section, findingsById.get(section.findingId ?? ''), index)
			)
		]
	};
}

function pageBackground(currentPage: number, width: number, height: number): Content {
	if (currentPage === 1) {
		return {
			canvas: [
				{ type: 'rect', x: 0, y: 0, w: width, h: height, color: BRAND.bg },
				{ type: 'rect', x: 0, y: 0, w: width, h: 210, color: BRAND.bg2 },
				{ type: 'rect', x: 0, y: 0, w: 7, h: height, color: BRAND.copper },
				{ type: 'line', x1: 44, y1: height - 84, x2: width - 44, y2: height - 84, lineColor: '#263044', lineWidth: 1 }
			]
		};
	}
	return {
		canvas: [
			{ type: 'rect', x: 0, y: 0, w: width, h: height, color: BRAND.canvas },
			{ type: 'rect', x: 28, y: 28, w: width - 56, h: height - 56, color: BRAND.paper }
		]
	};
}

function pageHeader(auditCase: AuditCase, pageWidth: number): Content {
	const context = compactHeaderContext(auditCase);
	const contentWidth = pageWidth - 88;
	return {
		margin: [44, 30, 44, 0],
		stack: [
			{
				columns: [
					{
						text: 'MAKINA LLM AUDIT',
						style: 'pageHeader',
						width: 'auto'
					},
					{ text: '', width: '*' },
					{
						text: context,
						style: 'pageHeaderMeta',
						alignment: 'right',
						noWrap: true,
						width: 'auto'
					} as Content
				],
				columnGap: 12
			},
			{
				canvas: [
					{
						type: 'line',
						x1: 0,
						y1: 0,
						x2: contentWidth,
						y2: 0,
						lineColor: '#e1e5ee',
						lineWidth: 0.5
					}
				],
				margin: [0, 9, 0, 0]
			}
		]
	};
}

function pageFooter(currentPage: number, pageCount: number): Content {
	return {
		margin: [44, 0, 44, 22],
		columns: [
			{ text: 'Generated by Makina', style: 'pageFooter' },
			{ text: `Page ${currentPage} / ${pageCount}`, style: 'pageFooter', alignment: 'right' }
		]
	};
}

function coverPage(
	auditCase: AuditCase,
	findings: Finding[],
	sections: AuditReportSection[],
	generatedAt: Date
): Content {
	const highest = highestSeverity(findings);
	const title = coverTitleFor(findings.length);

	return {
		pageBreak: 'after',
		margin: [8, 20, 8, 0],
		stack: [
			{
				columns: [
					{ svg: MAKINA_EYE_SVG, width: 58 },
					{
						stack: [
							{ text: 'MAKINA', style: 'coverBrand' },
							{ text: 'LLM vulnerability audit report', style: 'coverBrandSub' }
						],
						margin: [14, 9, 0, 0]
					}
				]
			},
			{ text: 'Security Audit Report', style: 'coverKicker', margin: [0, 94, 0, 0] },
			{ text: wrapPdfText(title), style: 'coverTitle' },
			{
				text: 'Evidence-bound analysis generated from scanner findings, source context, and the configured LLM audit workflow.',
				style: 'coverSubtitle'
			},
			{
				margin: [0, 88, 0, 0],
				table: {
					widths: ['*', '*', '*', '*'],
					body: [[
						metaTile('Language', auditCase.language),
						metaTile('Findings', String(findings.length)),
						metaTile('Max Impact', highest ? SEVERITY[highest].label : 'None'),
						metaTile('Generated', formatDate(generatedAt))
					]]
				},
				layout: 'noBorders'
			},
			{
				text: wrapPdfText(auditCase.scanId ? `Scan ID: ${auditCase.scanId}` : 'Scan ID: local audit context'),
				style: 'coverScanId',
				margin: [0, 24, 0, 0]
			}
		]
	};
}

function overviewPage(
	auditCase: AuditCase,
	findings: Finding[],
	sections: AuditReportSection[],
	generatedAt: Date
): Content {
	return {
		stack: [
			{ text: 'Audit Overview', style: 'sectionTitle' },
			{
				text: 'This report follows the Makina audit workflow: scanner evidence is preserved, each finding receives a stable MAKINA identifier, and exploitability is separated from raw sink detection.',
				style: 'paragraph'
			},
			{
				margin: [0, 14, 0, 18],
				table: {
					widths: ['*', '*', '*', '*'],
					body: [[
						summaryCell('Critical', countSeverity(findings, 'critical'), SEVERITY.critical.color),
						summaryCell('High', countSeverity(findings, 'high'), SEVERITY.high.color),
						summaryCell('Medium', countSeverity(findings, 'medium'), SEVERITY.medium.color),
						summaryCell('Low', countSeverity(findings, 'low'), SEVERITY.low.color)
					]]
				},
				layout: boxedLayout(BRAND.border)
			},
			{
				text: 'Scope',
				style: 'subsectionTitle'
			},
			{
				table: {
					widths: [95, '*'],
					body: [
						[
							labelCell('Language'),
							valueCell(auditCase.language)
						],
						[
							labelCell('Generated'),
							valueCell(formatDateTime(generatedAt))
						],
						[
							labelCell('Findings'),
							valueCell(String(findings.length))
						],
						[
							labelCell('Scan ID'),
							valueCell(auditCase.scanId || 'local audit context')
						]
					]
				},
				layout: boxedLayout(BRAND.border),
				margin: [0, 0, 0, 22]
			},
			{ text: 'Findings Index', style: 'subsectionTitle' },
			findingsIndex(sections, auditCase.findings)
		]
	};
}

function findingSection(section: AuditReportSection, finding: Finding | undefined, index: number): Content[] {
	const severity = finding ? SEVERITY[finding.severity] : null;
	const body = structuredReportContent(section) ??
		markdownBlocksToContent(parseMarkdown(section.source || 'No report body was generated.'));
	const headerFill = severity?.color ?? BRAND.violet;

	return [
		{
			pageBreak: 'before',
			margin: [0, 0, 0, 12],
			table: {
				widths: [6, '*'],
				body: [[
					{
						fillColor: headerFill,
						border: [false, false, false, false],
						text: '',
						margin: [0, 0, 0, 0]
					},
					{
						fillColor: '#ffffff',
						border: [false, true, true, true],
						borderColor: [BRAND.border, BRAND.border, BRAND.border, BRAND.border],
						stack: [
							{ text: section.id, style: 'findingId' },
							{ text: wrapPdfText(section.title), style: 'findingTitle' }
						],
						margin: [14, 14, 16, 14]
					}
				]]
			},
			layout: {
				hLineWidth: () => 0,
				vLineWidth: () => 0,
				paddingLeft: () => 0,
				paddingRight: () => 0,
				paddingTop: () => 0,
				paddingBottom: () => 0
			}
		},
		findingMeta(finding, index),
		...body
	];
}

function structuredReportContent(section: AuditReportSection): Content[] | null {
	const fields: { title: string; value: string | undefined; color: string }[] = [
		{ title: 'Summary', value: section.summary, color: BRAND.teal },
		{ title: 'Vulnerability Details', value: section.vulnerabilityDetails, color: BRAND.violet },
		{ title: 'Impact', value: section.impact, color: '#dc2626' },
		{ title: 'Proof of Concept', value: section.proofOfConcept, color: BRAND.copper },
		{ title: 'Remediation', value: section.remediation, color: '#16a34a' },
		{ title: 'Verification Notes', value: section.verificationNotes, color: '#64748b' },
		{ title: 'Confidence', value: section.confidence, color: '#2563eb' }
	];
	const blocks = fields.flatMap((field) => structuredFieldBlock(field.title, field.value, field.color));
	return blocks.length > 0 ? blocks : null;
}

function structuredFieldBlock(title: string, value: string | undefined, color: string): Content[] {
	const text = value?.trim();
	if (!text) return [];
	return [{
		margin: [0, 8, 0, 12],
		table: {
			widths: [4, '*'],
			body: [[
				{
					fillColor: color,
					border: [false, false, false, false],
					text: '',
					margin: [0, 0, 0, 0]
				},
				{
					fillColor: '#ffffff',
					border: [true, true, true, true],
					borderColor: [BRAND.border, BRAND.border, BRAND.border, BRAND.border],
					stack: [
						{ text: title, style: 'structuredHeading' },
						...markdownBlocksToContent(parseMarkdown(text))
					],
					margin: [10, 8, 10, 8]
				}
			]]
		},
		layout: {
			hLineWidth: () => 0,
			vLineWidth: () => 0,
			paddingLeft: () => 0,
			paddingRight: () => 0,
			paddingTop: () => 0,
			paddingBottom: () => 0
		}
	}];
}

function findingsIndex(sections: AuditReportSection[], findings: Finding[]): ContentTable {
	const findingsById = new Map(findings.map((finding) => [finding.id, finding]));
	const body: TableCell[][] = [
		[
			tableHeader('ID'),
			tableHeader('Impact'),
			tableHeader('CWE'),
			tableHeader('Rule'),
			tableHeader('Lines'),
			tableHeader('Title')
		]
	];

	for (const section of sections) {
		const finding = section.findingId ? findingsById.get(section.findingId) : null;
		const severity = finding ? SEVERITY[finding.severity] : null;
		body.push([
			tableText(section.id, true),
			badgeCell(severity?.label ?? 'Unscored', severity?.color ?? BRAND.muted, severity?.soft ?? '#eef1f5'),
			tableText(finding?.cwe ?? 'N/A'),
			tableText(finding?.rule_id ?? 'N/A'),
			tableText(finding ? lineRange(finding) : 'N/A'),
			tableText(section.title)
		]);
	}

	return {
		table: {
			headerRows: 1,
			widths: [62, 62, 54, 92, 50, '*'],
			body
		},
		layout: boxedLayout(BRAND.border)
	};
}

function findingMeta(finding: Finding | undefined, index: number): Content {
	if (!finding) {
		return {
			text: `No scanner finding metadata was attached for report section ${index + 1}.`,
			style: 'mutedParagraph',
			margin: [0, 12, 0, 14]
		};
	}

	const severity = SEVERITY[finding.severity];
	return {
		margin: [0, 12, 0, 18],
		table: {
			widths: [82, '*', 82, '*'],
			body: [
				[
					labelCell('Impact'),
					badgeCell(severity.label, severity.color, severity.soft),
					labelCell('Confidence'),
					valueCell(`${Math.round(finding.confidence * 100)}%`)
				],
				[
					labelCell('CWE'),
					valueCell(finding.cwe ?? 'N/A'),
					labelCell('Lines'),
					valueCell(lineRange(finding))
				],
				[
					labelCell('Rule'),
					valueCell(finding.rule_id),
					labelCell('Source'),
					valueCell(finding.source)
				]
			]
		},
		layout: boxedLayout(BRAND.border)
	};
}

function markdownBlocksToContent(blocks: BlockNode[]): Content[] {
	return blocks.flatMap((block): Content[] => {
		if (block.type === 'heading') {
			return [{
				text: inlineToFragments(block.children),
				style: block.level <= 2 ? 'markdownH2' : block.level === 3 ? 'markdownH3' : 'markdownH4'
			}];
		}
		if (block.type === 'paragraph') {
			return [{ text: inlineToFragments(block.children), style: 'paragraph' }];
		}
		if (block.type === 'code') {
			return [codeBlock(block.language, block.text)];
		}
		if (block.type === 'list') {
			const items = block.items.map((item) => ({ text: inlineToFragments(item) }));
			return [{
				[block.ordered ? 'ol' : 'ul']: items,
				margin: [0, 2, 0, 10],
				color: BRAND.ink
			} as unknown as Content];
		}
		return [markdownTable(block.headers, block.rows)];
	});
}

function inlineToFragments(nodes: InlineNode[]): PdfTextFragment[] {
	return nodes.flatMap((node): PdfTextFragment[] => {
		if (node.type === 'text') return [{ text: wrapPdfText(node.text) }];
		if (node.type === 'code') {
			return [{ text: wrapPdfText(node.text), color: BRAND.violet, background: '#eef0ff' }];
		}
		return inlineToFragments(node.children).map((child) => ({ ...child, bold: true }));
	});
}

function markdownTable(headers: InlineNode[][], rows: InlineNode[][][]): ContentTable {
	const widths = headers.map(() => '*');
	const body: TableCell[][] = [
		headers.map((header) => ({
			text: inlineToFragments(header),
			style: 'markdownTableHeader'
		}))
	];

	for (const row of rows) {
		body.push(row.map((cell) => ({ text: inlineToFragments(cell), style: 'markdownTableCell' })));
	}

	return {
		margin: [0, 8, 0, 14],
		table: { headerRows: 1, widths, body },
		layout: boxedLayout(BRAND.border)
	};
}

function codeBlock(language: string, text: string): ContentTable {
	const body: TableCell[][] = [];
	if (language) {
		body.push([{ text: language.toUpperCase(), style: 'codeLabel', fillColor: '#161d2c' }]);
	}
	body.push([{ text: wrapPdfText(text), style: 'codeBlock', fillColor: '#0b1120' }]);
	return {
		margin: [0, 8, 0, 14],
		table: { widths: ['*'], body },
		layout: {
			hLineColor: () => '#263044',
			vLineColor: () => '#263044',
			paddingLeft: () => 9,
			paddingRight: () => 9,
			paddingTop: () => 7,
			paddingBottom: () => 7
		}
	};
}

function metaTile(label: string, value: string): TableCell {
	return {
		stack: [
			{ text: label, style: 'coverMetaLabel' },
			{ text: value, style: 'coverMetaValue' }
		],
		fillColor: '#111827',
		border: [true, true, true, true],
		borderColor: ['#2b3447', '#2b3447', '#2b3447', '#2b3447'],
		margin: [8, 8, 8, 8]
	};
}

function summaryCell(label: string, value: number, color: string): TableCell {
	return {
		stack: [
			{ text: String(value), fontSize: 18, bold: true, color },
			{ text: label, fontSize: 8, bold: true, color: BRAND.muted, characterSpacing: 0.8 }
		],
		margin: [9, 8, 9, 8]
	};
}

function labelCell(text: string): TableCell {
	return { text, style: 'metaLabel', fillColor: '#f4f6fa' };
}

function valueCell(text: string): TableCell {
	return { text: wrapPdfText(text), style: 'metaValue' };
}

function tableHeader(text: string): TableCell {
	return { text, style: 'tableHeader' };
}

function tableText(text: string, bold = false): TableCell {
	return { text: wrapPdfText(text), bold, style: 'tableText' };
}

function badgeCell(label: string, color: string, fillColor: string): TableCell {
	return {
		text: label,
		bold: true,
		color,
		fillColor,
		alignment: 'center',
		margin: [5, 3, 5, 3],
		fontSize: 8
	};
}

function wrapPdfText(text: string): string {
	return text.replace(/\S{12,}/g, (token) =>
		token
			.replace(/([/\\._:-])/g, `$1${SOFT_BREAK}`)
			.replace(/([A-Za-z0-9]{18})(?=[A-Za-z0-9])/g, `$1${SOFT_BREAK}`)
	);
}

function boxedLayout(color: string) {
	return {
		hLineColor: () => color,
		vLineColor: () => color,
		paddingLeft: () => 7,
		paddingRight: () => 7,
		paddingTop: () => 7,
		paddingBottom: () => 7
	};
}

function highestSeverity(findings: Finding[]): Severity | null {
	const order: Severity[] = ['critical', 'high', 'medium', 'low'];
	return order.find((severity) => findings.some((finding) => finding.severity === severity)) ?? null;
}

function countSeverity(findings: Finding[], severity: Severity): number {
	return findings.filter((finding) => finding.severity === severity).length;
}

function lineRange(finding: Finding): string {
	return finding.line_start === finding.line_end
		? `L${finding.line_start}`
		: `L${finding.line_start}-${finding.line_end}`;
}

function formatDate(date: Date): string {
	return date.toISOString().slice(0, 10);
}

function formatDateTime(date: Date): string {
	return date.toLocaleString('en-US', {
		year: 'numeric',
		month: 'short',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit'
	});
}

function compactHeaderContext(auditCase: AuditCase): string {
	if (!auditCase.scanId) return auditCase.language;
	return `${auditCase.language} / ${compactScanId(auditCase.scanId)}`;
}

function compactScanId(scanId: string): string {
	if (scanId.length <= 24) return scanId;

	const knownPrefix = scanId.match(/^(audit-all|scan)-([0-9a-f]{8})/i);
	if (knownPrefix) return `${knownPrefix[1]}-${knownPrefix[2]}`;

	const firstSegment = scanId.split('-').filter(Boolean).slice(0, 2).join('-');
	if (firstSegment.length >= 12 && firstSegment.length <= 24) return firstSegment;

	return `${scanId.slice(0, 20)}...`;
}

function coverTitleFor(findingCount: number): string {
	if (findingCount <= 0) return 'Security Audit Report';
	return findingCount === 1 ? '1 Finding Analyzed' : `${findingCount} Findings Analyzed`;
}

function filenameForAudit(auditCase: AuditCase, generatedAt: Date): string {
	const date = formatDate(generatedAt).replaceAll('-', '');
	const scan = auditCase.scanId ? `-${auditCase.scanId.slice(0, 8)}` : '';
	return `makina-audit-${date}${scan}.pdf`;
}

function styles(): StyleDictionary {
	return {
		coverBrand: { color: BRAND.ivory, fontSize: 15, bold: true, characterSpacing: 1.5 },
		coverBrandSub: { color: '#a8b0c2', fontSize: 9, margin: [0, 5, 0, 0] },
		coverKicker: { color: BRAND.teal, fontSize: 9, bold: true, characterSpacing: 1.2 },
		coverTitle: {
			color: BRAND.ivory,
			fontSize: 36,
			bold: true,
			lineHeight: 1.05,
			margin: [0, 14, 44, 0]
		},
		coverSubtitle: { color: '#b9c0cf', fontSize: 13, margin: [0, 18, 96, 0] },
		coverMetaLabel: { color: '#8891a4', fontSize: 8, bold: true, characterSpacing: 0.6 },
		coverMetaValue: { color: BRAND.ivory, fontSize: 12, bold: true, margin: [0, 5, 0, 0] },
		coverScanId: { color: '#8b95aa', fontSize: 9 },
		pageHeader: { color: BRAND.violet, fontSize: 8, bold: true, characterSpacing: 1.2 },
		pageHeaderMeta: { color: BRAND.muted, fontSize: 8 },
		pageFooter: { color: '#8b95aa', fontSize: 8 },
		sectionTitle: { color: BRAND.ink, fontSize: 22, bold: true, margin: [0, 0, 0, 10] },
		subsectionTitle: { color: BRAND.ink, fontSize: 13, bold: true, margin: [0, 8, 0, 8] },
		paragraph: { color: BRAND.ink, fontSize: 10, margin: [0, 0, 0, 9] },
		mutedParagraph: { color: BRAND.muted, fontSize: 9 },
		metaLabel: { color: BRAND.muted, fontSize: 8, bold: true, characterSpacing: 0.4 },
		metaValue: { color: BRAND.ink, fontSize: 9 },
		tableHeader: { color: BRAND.muted, fillColor: '#f4f6fa', fontSize: 8, bold: true },
		tableText: { color: BRAND.ink, fontSize: 8 },
		findingId: { color: BRAND.violet, fontSize: 9, bold: true, characterSpacing: 1.1 },
		findingTitle: { color: BRAND.ink, fontSize: 18, bold: true, margin: [0, 5, 0, 0] },
		findingIdOnColor: { color: '#f8fafc', fontSize: 9, bold: true, characterSpacing: 1.1 },
		findingTitleOnColor: { color: '#ffffff', fontSize: 18, bold: true, margin: [0, 4, 0, 0] },
		structuredHeading: { color: BRAND.ink, fontSize: 12, bold: true, margin: [0, 0, 0, 5] },
		markdownH2: {
			color: BRAND.ink,
			fontSize: 15,
			bold: true,
			margin: [0, 12, 0, 7]
		},
		markdownH3: {
			color: BRAND.violet,
			fontSize: 11,
			bold: true,
			margin: [0, 10, 0, 5]
		},
		markdownH4: {
			color: BRAND.ink,
			fontSize: 10,
			bold: true,
			margin: [0, 8, 0, 4]
		},
		markdownTableHeader: { color: BRAND.muted, fillColor: '#f4f6fa', fontSize: 8, bold: true },
		markdownTableCell: { color: BRAND.ink, fontSize: 8 },
		codeLabel: { color: '#7dd3fc', fontSize: 7, bold: true, characterSpacing: 0.5 },
		codeBlock: { color: '#e5e7eb', fontSize: 8, lineHeight: 1.25 }
	} as StyleDictionary;
}
