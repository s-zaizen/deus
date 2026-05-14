import type { HighlighterCore } from 'shiki/core';
import { severityTone } from '$lib/theme';
import type { Severity } from '$lib/types';

let instance: HighlighterCore | null = null;
let loading: Promise<HighlighterCore> | null = null;

async function getInstance(): Promise<HighlighterCore> {
	if (instance) return instance;
	if (!loading) {
		loading = (async () => {
			const { createHighlighterCore } = await import('shiki/core');
			const { createOnigurumaEngine } = await import('shiki/engine/oniguruma');
			const h = await createHighlighterCore({
				themes: [import('shiki/themes/vitesse-dark.mjs')],
				langs: [
					import('shiki/langs/python.mjs'),
					import('shiki/langs/javascript.mjs'),
					import('shiki/langs/typescript.mjs'),
					import('shiki/langs/rust.mjs'),
					import('shiki/langs/go.mjs'),
					import('shiki/langs/java.mjs'),
					import('shiki/langs/ruby.mjs'),
					import('shiki/langs/c.mjs'),
					import('shiki/langs/cpp.mjs')
				],
				engine: createOnigurumaEngine(import('shiki/wasm'))
			});
			instance = h;
			return h;
		})();
	}
	return loading;
}

export async function preloadHighlighter(): Promise<void> {
	await getInstance();
}

export async function highlightSnippet(
	code: string,
	lang: string,
	lineStart: number,
	lineEnd: number,
	severity: string
): Promise<string> {
	const h = await getInstance();
	const bg = severityTone(severity as Severity).highlight;
	const safeLang = lang === 'auto' ? 'text' : lang;

	return h.codeToHtml(code, {
		lang: safeLang,
		theme: 'vitesse-dark',
		transformers: [
			{
				line(node, line) {
					const actualLine = line + lineStart - 1;
					if (actualLine >= lineStart && actualLine <= lineEnd) {
						this.addClassToHast(node, 'highlighted-line');
						node.properties['style'] =
							(node.properties['style'] ?? '') + `background:${bg};`;
					}
				}
			}
		]
	});
}
