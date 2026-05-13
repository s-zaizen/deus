export type InlineNode =
	| { type: 'text'; text: string }
	| { type: 'strong'; children: InlineNode[] }
	| { type: 'code'; text: string };

export type BlockNode =
	| { type: 'heading'; level: number; children: InlineNode[] }
	| { type: 'paragraph'; children: InlineNode[] }
	| { type: 'code'; language: string; text: string }
	| { type: 'list'; ordered: boolean; items: InlineNode[][] }
	| { type: 'table'; headers: InlineNode[][]; rows: InlineNode[][][] };

export function parseInline(text: string): InlineNode[] {
	const nodes: InlineNode[] = [];
	let remaining = text;

	while (remaining.length > 0) {
		const codeMatch = remaining.match(/^`([^`]+)`/);
		if (codeMatch) {
			nodes.push({ type: 'code', text: codeMatch[1] });
			remaining = remaining.slice(codeMatch[0].length);
			continue;
		}

		const strongMatch = remaining.match(/^(\*\*|__)(.*?)\1/);
		if (strongMatch) {
			nodes.push({ type: 'strong', children: parseInline(strongMatch[2]) });
			remaining = remaining.slice(strongMatch[0].length);
			continue;
		}

		const nextSpecial = remaining.search(/[`_*]/);
		if (nextSpecial === -1) {
			nodes.push({ type: 'text', text: remaining });
			break;
		} else if (nextSpecial === 0) {
			nodes.push({ type: 'text', text: remaining[0] });
			remaining = remaining.slice(1);
		} else {
			nodes.push({ type: 'text', text: remaining.slice(0, nextSpecial) });
			remaining = remaining.slice(nextSpecial);
		}
	}

	return nodes;
}

export function parseMarkdown(src: string): BlockNode[] {
	const lines = src.split('\n');
	const blocks: BlockNode[] = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];

		if (line.trim() === '') {
			i++;
			continue;
		}

		if (line.startsWith('```')) {
			const lang = line.slice(3).trim();
			let content = '';
			i++;
			while (i < lines.length && !lines[i].startsWith('```')) {
				content += (content ? '\n' : '') + lines[i];
				i++;
			}
			i++;
			blocks.push({ type: 'code', language: lang, text: content });
			continue;
		}

		const headingMatch = line.match(/^(#{1,6})\s+(.+?)(?:\s+#+\s*)?$/);
		if (headingMatch) {
			blocks.push({
				type: 'heading',
				level: headingMatch[1].length,
				children: parseInline(headingMatch[2].trim())
			});
			i++;
			continue;
		}

		if (looksLikeTableStart(lines, i)) {
			const headers = splitTableRow(lines[i]).map(parseInline);
			i += 2;
			const rows: InlineNode[][][] = [];
			while (i < lines.length && isTableRow(lines[i])) {
				rows.push(splitTableRow(lines[i]).map(parseInline));
				i++;
			}
			blocks.push({ type: 'table', headers, rows });
			continue;
		}

		const ulMatch = line.match(/^(\s*)[-*+]\s+(.*)$/);
		const olMatch = line.match(/^(\s*)\d+\.\s+(.*)$/);
		if (ulMatch || olMatch) {
			const ordered = !ulMatch;
			const items: InlineNode[][] = [];

			while (i < lines.length) {
				const currentLine = lines[i];
				const currentUl = currentLine.match(/^(\s*)[-*+]\s+(.*)$/);
				const currentOl = currentLine.match(/^(\s*)\d+\.\s+(.*)$/);

				if ((!ordered && currentUl) || (ordered && currentOl)) {
					const text = ordered ? currentOl![2] : currentUl![2];
					items.push(parseInline(text));
					i++;
				} else if (currentLine.trim() === '') {
					let j = i + 1;
					while (j < lines.length && lines[j].trim() === '') j++;
					if (j < lines.length) {
						const nextUl = lines[j].match(/^(\s*)[-*+]\s+(.*)$/);
						const nextOl = lines[j].match(/^(\s*)\d+\.\s+(.*)$/);
						if ((!ordered && nextUl) || (ordered && nextOl)) {
							i = j;
							continue;
						}
					}
					break;
				} else {
					break;
				}
			}

			blocks.push({ type: 'list', ordered, items });
			continue;
		}

		let text = '';
		while (i < lines.length && lines[i].trim() !== '') {
			if (text) text += ' ';
			text += lines[i].trim();
			i++;
		}
		blocks.push({ type: 'paragraph', children: parseInline(text) });
	}

	return blocks;
}

function isTableRow(line: string) {
	const trimmed = line.trim();
	return trimmed.startsWith('|') && trimmed.endsWith('|') && trimmed.includes('|');
}

function isTableSeparator(line: string) {
	return /^\s*\|?[\s:-]+\|[\s|:-]*$/.test(line);
}

function looksLikeTableStart(lines: string[], index: number) {
	return isTableRow(lines[index] ?? '') && isTableSeparator(lines[index + 1] ?? '');
}

function splitTableRow(line: string) {
	return line
		.trim()
		.replace(/^\|/, '')
		.replace(/\|$/, '')
		.split('|')
		.map((cell) => cell.trim());
}
