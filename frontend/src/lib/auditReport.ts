export interface AuditReportSection {
	id: string;
	title: string;
	source: string;
	findingId: string | null;
	summary?: string;
	vulnerabilityDetails?: string;
	impact?: string;
	proofOfConcept?: string;
	remediation?: string;
	verificationNotes?: string;
	confidence?: string;
}

export interface AuditReportSectionWire {
	id: string;
	finding_id: string | null;
	title: string;
	summary: string;
	vulnerability_details: string;
	impact: string;
	proof_of_concept: string;
	remediation: string;
	verification_notes: string;
	confidence: string;
}

export function reportIdForIndex(index: number) {
	return `MAKINA-${String(index + 1).padStart(3, '0')}`;
}

export function splitReportMarkdown(markdown: string): Omit<AuditReportSection, 'findingId'>[] {
	const source = markdown.trim();
	if (!source) return [];

	const matches = [...source.matchAll(/^#\s+(MAKINA-\d{3})(?::\s*(.*?))?\s*$/gm)];
	if (matches.length === 0) {
		return [{ id: 'MAKINA-001', title: 'Audit Report', source }];
	}

	return matches.map((match, index) => {
		const start = match.index ?? 0;
		const headerEnd = start + match[0].length;
		const nextStart = matches[index + 1]?.index ?? source.length;
		return {
			id: match[1],
			title: match[2]?.trim() || 'Audit Report',
			source: source.slice(headerEnd, nextStart).trim()
		};
	});
}

export function mapAuditReportSections(
	markdown: string,
	auditFindingIds: string[],
	fallbackFindingIds: string[] = []
): AuditReportSection[] {
	return splitReportMarkdown(markdown).map((section, index) => ({
		...section,
		findingId: auditFindingIds[index] ?? fallbackFindingIds[index] ?? null
	}));
}

export function reportSectionFromWire(section: AuditReportSectionWire): AuditReportSection {
	const normalized = {
		id: section.id,
		title: section.title || 'Audit Report',
		findingId: section.finding_id,
		summary: section.summary || '',
		vulnerabilityDetails: section.vulnerability_details || '',
		impact: section.impact || '',
		proofOfConcept: section.proof_of_concept || '',
		remediation: section.remediation || '',
		verificationNotes: section.verification_notes || '',
		confidence: section.confidence || ''
	};

	return {
		...normalized,
		source: structuredSectionMarkdown(normalized)
	};
}

export function structuredSectionMarkdown(section: Omit<AuditReportSection, 'source'>): string {
	return [
		markdownField('Summary', section.summary),
		markdownField('Vulnerability Details', section.vulnerabilityDetails),
		markdownField('Impact', section.impact),
		markdownField('Proof of Concept', section.proofOfConcept),
		markdownField('Remediation', section.remediation),
		markdownField('Verification Notes', section.verificationNotes),
		markdownField('Confidence', section.confidence)
	]
		.filter(Boolean)
		.join('\n\n');
}

function markdownField(title: string, value: string | undefined): string {
	const text = value?.trim();
	return text ? `## ${title}\n${text}` : '';
}
