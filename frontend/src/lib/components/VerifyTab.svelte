<script lang="ts">
	import { highlightSnippet } from '$lib/highlighter';
	import { PUBLIC_MODE } from '$lib/flags';
	import { severityTone } from '$lib/theme';
	import type { Label, VerifyCase } from '$lib/types';

	let {
		cases,
		onlabel,
		onsubmit,
		onclose
	}: {
		cases: VerifyCase[];
		onlabel: (caseNo: number, findingId: string, label: Label) => void;
		onsubmit: (caseNo: number) => Promise<void>;
		onclose: (caseNo: number) => Promise<void>;
	} = $props();

	const langColor: Record<string, string> = {
		python: 'text-blue-400 bg-blue-950 border-blue-800',
		javascript: 'text-yellow-400 bg-yellow-950 border-yellow-800',
		typescript: 'text-sky-400 bg-sky-950 border-sky-800',
		rust: 'text-orange-400 bg-orange-950 border-orange-800',
		go: 'text-cyan-400 bg-cyan-950 border-cyan-800',
		java: 'text-red-400 bg-red-950 border-red-800',
		ruby: 'text-rose-400 bg-rose-950 border-rose-800',
		c: 'text-gray-400 bg-gray-800 border-gray-600',
		cpp: 'text-purple-400 bg-purple-950 border-purple-800'
	};
	function formatDate(iso: string) {
		const d = new Date(iso);
		const date = d.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' });
		const time = d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' });
		return `${date} ${time}`;
	}

	// Filter state
	let searchQuery = $state('');
	let filterLang = $state<string | null>(null);

	const availableLangs = $derived([...new Set(cases.map((c) => c.language))]);

	const filteredCases = $derived(
		cases.filter((vc) => {
			if (filterLang && vc.language !== filterLang) return false;
			if (searchQuery.trim()) {
				const q = searchQuery.toLowerCase();
				if (
					!vc.cveId?.toLowerCase().includes(q) &&
					!vc.findings.some(
						(f) =>
							f.rule_id.toLowerCase().includes(q) ||
							(f.cwe?.toLowerCase().includes(q) ?? false) ||
							f.message.toLowerCase().includes(q)
					)
				)
					return false;
			}
			return true;
		})
	);

	// Per-case expand state and submitting state — collapsed by default
	let expandedCases = $state<Record<number, boolean>>({});
	let submittingCases = $state<Record<number, boolean>>({});
	let closingCases = $state<Record<number, boolean>>({});

	// Highlighted code cache: keyed by findingId. Populated lazily on expand.
	let codeCache = $state<Record<string, string>>({});

	function highlightCase(vc: VerifyCase) {
		for (const f of vc.findings) {
			if (!f.code_snippet || codeCache[f.id] !== undefined) continue;
			codeCache[f.id] = ''; // sentinel: in-progress
			const { id, code_snippet, line_start, line_end, severity } = f;
			highlightSnippet(code_snippet, vc.language, line_start, line_end, severity)
				.then((html) => { codeCache[id] = html; })
				.catch(() => { /* keep sentinel, falls back to plain <pre> */ });
		}
	}

	function isExpanded(caseNo: number) {
		return expandedCases[caseNo] === true;
	}

	function toggleExpand(vc: VerifyCase) {
		const next = !isExpanded(vc.caseNo);
		expandedCases[vc.caseNo] = next;
		if (next) highlightCase(vc);
	}

	async function handleSubmit(caseNo: number) {
		submittingCases[caseNo] = true;
		try {
			await onsubmit(caseNo);
		} finally {
			submittingCases[caseNo] = false;
		}
	}

	async function handleClose(caseNo: number) {
		closingCases[caseNo] = true;
		try {
			await onclose(caseNo);
		} finally {
			closingCases[caseNo] = false;
		}
	}

</script>

{#if PUBLIC_MODE}
	<div class="flex-1 flex items-center justify-center bg-[var(--mk-bg)]">
		<div class="max-w-md px-6 text-center">
			<div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-xl border border-amber-900/70 bg-amber-950/25">
				<svg class="h-7 w-7 text-amber-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round"
						d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
				</svg>
			</div>
			<p class="text-sm font-semibold text-gray-300">Verify is disabled in public demo mode</p>
			<p class="mt-2 text-sm leading-relaxed text-gray-500">
				makina.sh runs a frozen read-only model. TP/FP labels, case closing, and Knowledge submission are disabled so public traffic cannot modify training data.
			</p>
			<p class="mt-3 text-xs leading-relaxed text-gray-600">
				Run Makina locally or in a private deployment to use the continuous learning workflow.
			</p>
		</div>
	</div>
{:else if cases.length === 0}
	<div class="flex-1 flex items-center justify-center bg-[var(--mk-bg)]">
		<div class="text-center max-w-sm px-4">
			<div class="w-16 h-16 mx-auto mb-4 rounded-xl bg-[var(--mk-bg-elevated)] border border-dashed border-[var(--mk-border-strong)] flex items-center justify-center">
				<svg class="w-7 h-7 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
					<path stroke-linecap="round" stroke-linejoin="round"
						d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
				</svg>
			</div>
			<p class="text-base text-gray-400 font-medium">All caught up!</p>
			<p class="text-sm text-gray-600 mt-1 leading-relaxed">
				No cases waiting for review. Go to the Scan tab to analyze code and send findings here.
			</p>
		</div>
	</div>
{:else}
	<div class="flex-1 overflow-y-auto px-6 py-5 bg-[var(--mk-bg)]">
		<div class="max-w-full lg:max-w-2xl xl:max-w-3xl mx-auto space-y-3">
			<!-- Search + language filter -->
			<div class="flex flex-col gap-2 mb-3">
				<input
					bind:value={searchQuery}
					type="text"
					placeholder="Search CVE, rule, CWE, message…"
					class="w-full bg-[var(--mk-bg-elevated)] border border-[var(--mk-border)] rounded-md px-3 py-1.5 text-xs text-[var(--mk-text)] placeholder-gray-600 focus:outline-none focus:border-violet-500/70 transition-colors"
				/>
				{#if availableLangs.length > 1}
					<div class="flex flex-wrap gap-1">
						{#each availableLangs as lang}
							<button
								onclick={() => { filterLang = filterLang === lang ? null : lang; }}
								class={[
									'text-xs px-2 py-1 rounded border font-mono text-center min-w-[64px] transition-colors cursor-pointer',
									filterLang === lang
										? 'bg-violet-700 border-violet-600 text-white'
										: 'bg-[var(--mk-bg-elevated)] border-[var(--mk-border)] text-gray-500 hover:text-[var(--mk-text-soft)]'
								].join(' ')}
							>{lang.toUpperCase()}</button>
						{/each}
						{#if filterLang}
							<button
								onclick={() => { filterLang = null; }}
								class="text-xs px-2 py-1 rounded border bg-[var(--mk-bg-elevated)] border-[var(--mk-border)] text-gray-600 hover:text-[var(--mk-text-soft)] transition-colors cursor-pointer"
							>✕ clear</button>
						{/if}
					</div>
				{/if}
			</div>

			<p class="text-xs text-gray-600">
				{#if filteredCases.length !== cases.length}
					{filteredCases.length} of {cases.length} case{cases.length !== 1 ? 's' : ''} shown
				{:else}
					{cases.length} case{cases.length !== 1 ? 's' : ''} pending verification
				{/if}
			</p>

			{#if filteredCases.length === 0}
				<div class="flex flex-col items-center gap-2 py-8 text-center">
					<p class="text-sm text-gray-600">No cases match the current filter.</p>
					<button
						onclick={() => { searchQuery = ''; filterLang = null; }}
						class="text-xs text-violet-300 hover:text-violet-200 transition-colors cursor-pointer"
					>Clear filters</button>
				</div>
			{/if}

			{#each filteredCases as vc (vc.caseNo)}
				{@const labeledCount = Object.keys(vc.labels).length}
				{@const tpCount = Object.values(vc.labels).filter((l) => l === 'tp').length}
				{@const fpCount = Object.values(vc.labels).filter((l) => l === 'fp').length}
				{@const expanded = isExpanded(vc.caseNo)}
				{@const submitting = submittingCases[vc.caseNo] ?? false}
				{@const closing = closingCases[vc.caseNo] ?? false}

				<div class="rounded-xl border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] overflow-hidden">
					<!-- Header -->
					<button
						onclick={() => toggleExpand(vc)}
						class="w-full flex items-center gap-2.5 px-4 py-3 hover:bg-[var(--mk-bg-hover)] transition-colors text-left"
					>
						<span class="font-mono text-sm font-bold text-violet-200 shrink-0">
							#{String(vc.caseNo).padStart(4, '0')}
						</span>
						{#if vc.cveId}
							<span class="font-mono text-xs text-amber-400 shrink-0">{vc.cveId}</span>
						{/if}
						<span class="text-xs text-gray-500 shrink-0">{formatDate(vc.submittedAt)}</span>
						<span class={`text-xs px-1.5 py-0.5 rounded border font-mono shrink-0 ${langColor[vc.language] ?? 'text-gray-400 bg-gray-800 border-gray-600'}`}>
							{vc.language}
						</span>
						<span class="text-xs text-gray-500 shrink-0">{vc.findings.length} findings</span>
						{#if labeledCount > 0}
							<span class="text-xs text-gray-600 shrink-0">
								{#if tpCount > 0}<span class="text-teal-500">TP:{tpCount}</span>{/if}
								{#if tpCount > 0 && fpCount > 0}<span class="text-gray-700 mx-1">·</span>{/if}
								{#if fpCount > 0}<span class="text-red-700">FP:{fpCount}</span>{/if}
							</span>
						{/if}
						<svg
							class={`ml-auto w-4 h-4 text-gray-600 transition-transform shrink-0 ${expanded ? 'rotate-180' : ''}`}
							fill="none" viewBox="0 0 24 24" stroke="currentColor"
						>
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
						</svg>
					</button>

					<!-- Body -->
					{#if expanded}
						<div class="border-t border-[var(--mk-border)] divide-y divide-[var(--mk-border)]/70">
							{#each vc.findings as f (f.id)}
								{@const labeled = vc.labels[f.id] ?? null}

								<div class="px-4 py-3 flex gap-3">
									<div class="flex-1 min-w-0 space-y-2">
										<!-- Finding meta -->
										<div class="flex flex-wrap items-center gap-2">
											<span class={`text-xs font-bold uppercase ${severityTone(f.severity).text}`}>
												{f.severity}
											</span>
											<span class="font-mono text-xs text-gray-500">{f.rule_id}</span>
											{#if f.cwe}
												<span class="text-xs text-gray-600 font-mono px-1 bg-[var(--mk-border)] rounded border border-[var(--mk-border-strong)]">
													{f.cwe}
												</span>
											{/if}
											<span class="text-xs text-gray-700 font-mono">
												{f.line_end > f.line_start ? `L${f.line_start}–${f.line_end}` : `L${f.line_start}`}
											</span>
										</div>

										<!-- Message -->
										<p class="text-xs text-gray-300 leading-snug">{f.message}</p>

										<!-- Code snippet -->
										{#if f.code_snippet}
											<div class="rounded border border-[var(--mk-border)] overflow-hidden">
												{#if codeCache[f.id]}
													<div
														class="shiki-snippet"
														style="max-height:8rem; overflow-y:auto; font-size:0.68rem; line-height:1.5;"
													>
														{@html codeCache[f.id]}
													</div>
												{:else}
													<pre class="text-gray-300 text-xs p-2 overflow-x-auto max-h-32">{f.code_snippet}</pre>
												{/if}
											</div>
										{/if}
									</div>

									<!-- TP / FP buttons -->
									<div class="flex flex-col gap-1.5 shrink-0 pt-0.5">
										<button
											onclick={() => onlabel(vc.caseNo, f.id, 'tp')}
											disabled={labeled !== null}
											class={[
												'text-xs px-3 py-1 rounded border font-medium transition-colors',
												labeled === 'tp'
													? 'bg-teal-700 border-teal-600 text-white'
													: labeled === 'fp'
														? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-600 cursor-not-allowed'
														: 'bg-teal-950/35 border-teal-700/60 text-teal-300 hover:bg-teal-950/65 cursor-pointer'
											].join(' ')}
										>
											TP
										</button>
										<button
											onclick={() => onlabel(vc.caseNo, f.id, 'fp')}
											disabled={labeled !== null}
											class={[
												'text-xs px-3 py-1 rounded border font-medium transition-colors',
												labeled === 'fp'
													? 'bg-red-700 border-red-600 text-white'
													: labeled === 'tp'
														? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-600 cursor-not-allowed'
														: 'bg-red-900/30 border-red-700/60 text-red-400 hover:bg-red-900/60 cursor-pointer'
											].join(' ')}
										>
											FP
										</button>
									</div>
								</div>
							{/each}

							<!-- Submit footer -->
							<div class="px-4 py-3 bg-[var(--mk-bg-panel)] flex items-center justify-between gap-3">
								<span class="text-xs text-gray-600">
									{labeledCount}/{vc.findings.length} labeled
									{#if labeledCount > 0}
										&nbsp;·&nbsp;<span class="text-teal-500">{tpCount} TP</span>
										&nbsp;·&nbsp;<span class="text-red-600">{fpCount} FP</span>
									{/if}
								</span>
								<div class="flex items-center gap-2">
									<button
										onclick={() => handleClose(vc.caseNo)}
										disabled={closing || submitting}
										class={[
											'px-4 py-1.5 rounded border text-sm font-semibold transition-colors',
											closing || submitting
												? 'border-[var(--mk-border)] bg-[var(--mk-border)] text-gray-600 cursor-not-allowed'
												: 'border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] text-gray-400 hover:border-violet-500/60 hover:text-[var(--mk-text)] cursor-pointer'
										].join(' ')}
									>
										{closing ? 'Closing…' : 'Close Case'}
									</button>
									<button
										onclick={() => handleSubmit(vc.caseNo)}
										disabled={submitting || closing || labeledCount === 0}
										class={[
											'px-5 py-1.5 rounded text-sm font-semibold transition-colors',
											submitting || closing || labeledCount === 0
												? 'bg-[var(--mk-border)] text-gray-600 cursor-not-allowed'
												: 'bg-violet-600 hover:bg-violet-500 text-white cursor-pointer'
										].join(' ')}
									>
										{submitting ? 'Submitting…' : 'Submit to Knowledge'}
									</button>
								</div>
							</div>
						</div>
					{/if}
				</div>
			{/each}
		</div>
	</div>
{/if}
