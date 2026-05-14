<script lang="ts">
	import { onMount } from 'svelte';
	import { highlightSnippet } from '$lib/highlighter';
	import { severityTone } from '$lib/theme';
	import type { Finding, Label, Language } from '$lib/types';

	let {
		finding,
		language,
		onlabel,
		onreview,
		onclose,
		onfocus,
		focused = false,
		readonly = false,
		existingLabel = null,
		queuedForReview = false
	}: {
		finding: Finding;
		language: Language;
		onlabel?: (id: string, label: Label) => Promise<void>;
		onreview?: (id: string) => Promise<void> | void;
		onclose?: (id: string) => Promise<void> | void;
		onfocus?: () => void;
		focused?: boolean;
		readonly?: boolean;
		existingLabel?: Label | null;
		queuedForReview?: boolean;
	} = $props();

	let interactiveLabel = $state<Label | null>(null);
	const labeled = $derived<Label | null>(readonly ? (existingLabel ?? null) : interactiveLabel);
	let loading = $state(false);
	let closing = $state(false);
	let highlightedHtml = $state('');

	const tone = $derived(severityTone(finding.severity));
	const borderColor = $derived(tone.border);
	const barColor = $derived(tone.track);
	const confidencePct = $derived(Math.round(finding.confidence * 100));
	const lineRange = $derived(
		finding.line_end > finding.line_start
			? `Lines ${finding.line_start}–${finding.line_end}`
			: `Line ${finding.line_start}`
	);
	const isSemgrep = $derived(finding.source === 'semgrep');
	const isManual = $derived(finding.source === 'manual');

	onMount(async () => {
		if (finding.code_snippet) {
			try {
				highlightedHtml = await highlightSnippet(
					finding.code_snippet,
					language,
					finding.line_start,
					finding.line_end,
					finding.severity
				);
			} catch {
				highlightedHtml = `<pre class="text-gray-300 text-xs p-2">${finding.code_snippet}</pre>`;
			}
		}
	});

	async function handleLabel(label: Label, e: MouseEvent) {
		e.stopPropagation();
		if (!onlabel) return;
		loading = true;
		try {
			await onlabel(finding.id, label);
			interactiveLabel = label;
		} finally {
			loading = false;
		}
	}

	async function handleReview(e: MouseEvent) {
		e.stopPropagation();
		if (!onreview || queuedForReview) return;
		loading = true;
		try {
			await onreview(finding.id);
		} finally {
			loading = false;
		}
	}

	async function handleClose(e: MouseEvent) {
		e.stopPropagation();
		if (!onclose) return;
		closing = true;
		try {
			await onclose(finding.id);
		} finally {
			closing = false;
		}
	}
</script>

<div
	role="button"
	tabindex="0"
	onclick={onfocus}
	onkeydown={(e) => e.key === 'Enter' && onfocus?.()}
	class={[
		'rounded border bg-[var(--mk-bg-elevated)] border-l-4 p-3 flex flex-col gap-2 transition-all',
		borderColor,
		focused
			? 'border-violet-500/70 ring-1 ring-violet-500/45 shadow-[0_0_22px_rgba(79,70,229,0.14)] cursor-default'
			: 'border-[var(--mk-border-strong)] cursor-pointer hover:border-[#3a4260] hover:bg-[var(--mk-bg-hover)]'
	].join(' ')}
>
	<!-- Header -->
	<div class="flex flex-wrap items-center gap-1.5">
		<span
			class={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border ${tone.badge} uppercase tracking-wide shrink-0`}
		>
			{finding.severity}
		</span>
		<span class="font-mono text-[10px] text-gray-300 shrink-0">{finding.rule_id}</span>
		{#if finding.cwe}
			<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 text-gray-400 border border-gray-600 shrink-0">
				{finding.cwe}
			</span>
		{/if}
		<span
			class={`text-[10px] px-1.5 py-0.5 rounded font-mono border shrink-0 ${
				isSemgrep
					? 'bg-blue-950 text-blue-400 border-blue-800'
					: isManual
						? 'bg-teal-950 text-teal-400 border-teal-800'
						: 'bg-purple-950 text-purple-400 border-purple-800'
			}`}
		>
			{finding.source.toUpperCase()}
		</span>
		{#if finding.is_uncertain}
			<span class="text-[10px] px-1.5 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700 shrink-0">
				Uncertain
			</span>
		{/if}
		{#if focused}
			<span class="ml-auto text-[10px] text-[var(--mk-text-soft)] shrink-0">↑ in editor</span>
		{/if}
	</div>

	<!-- Message -->
	<p class="text-xs text-gray-200 leading-snug">{finding.message}</p>

	<!-- Code snippet -->
	{#if finding.code_snippet}
		<div class="rounded border border-[var(--mk-border)] overflow-hidden">
			<div class="flex items-center justify-between px-3 py-1 bg-[var(--mk-bg-hover)] border-b border-[var(--mk-border)]">
				<span class="text-xs font-mono text-gray-500">{lineRange}</span>
			</div>
			{#if highlightedHtml}
				<div
					class="shiki-snippet max-h-40 overflow-y-auto text-[11px] leading-relaxed"
				>
					{@html highlightedHtml}
				</div>
			{:else}
				<pre class="text-gray-300 text-xs p-2 overflow-x-auto max-h-40">{finding.code_snippet}</pre>
			{/if}
		</div>
	{/if}

	<!-- Confidence bar -->
	<div class="flex items-center gap-2">
		<span class="text-xs text-gray-500 w-20 shrink-0">Confidence {confidencePct}%</span>
		<div class="flex-1 h-1.5 bg-[var(--mk-border)] rounded-full overflow-hidden">
			<div class={`h-full rounded-full ${barColor}`} style="width:{confidencePct}%"></div>
		</div>
	</div>

	<!-- Review actions or readonly label badge -->
	{#if readonly}
		{#if labeled}
			<div class="flex items-center gap-2 mt-1">
				<span class={[
					'text-xs font-semibold px-3 py-1 rounded border',
					labeled === 'tp'
						? 'bg-teal-700 border-teal-600 text-white'
						: 'bg-red-700 border-red-600 text-white'
				].join(' ')}>
					{labeled === 'tp' ? '✓ True Positive' : '✗ False Positive'}
				</span>
			</div>
		{/if}
	{:else if !onlabel}
		<div class="grid grid-cols-1 gap-2 mt-1">
			{#if onreview}
				<button
					onclick={handleReview}
					disabled={loading || closing || queuedForReview}
					class={[
						'flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
						queuedForReview
							? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-500 cursor-not-allowed'
							: 'bg-violet-950/35 border-violet-700 text-violet-200 hover:bg-violet-950/60 cursor-pointer'
					].join(' ')}
				>
					<span>{queuedForReview ? '✓' : '→'}</span>
					{queuedForReview ? 'In Review' : loading ? 'Submitting...' : 'Submit to Review'}
				</button>
			{/if}

			{#if onclose}
				<button
					onclick={handleClose}
					disabled={loading || closing}
					class="flex items-center justify-center gap-1.5 rounded border border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:border-violet-500/50 hover:bg-[var(--mk-bg-hover)] disabled:cursor-not-allowed disabled:opacity-50"
				>
					<span>&#8722;</span>
					{closing ? 'Closing...' : 'Close Case'}
				</button>
			{/if}
		</div>
	{:else}
		<div class="grid grid-cols-2 gap-2 mt-1">
			<button
				onclick={(e) => handleLabel('tp', e)}
				disabled={loading || closing || labeled !== null}
				class={[
					'flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
					labeled === 'tp'
						? 'bg-teal-700 border-teal-600 text-white'
						: labeled === 'fp'
							? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-500 cursor-not-allowed'
							: 'bg-teal-950/40 border-teal-700 text-teal-300 hover:bg-teal-950/70 cursor-pointer'
				].join(' ')}
			>
				{#if labeled === 'tp'}
					<svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
						<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
					</svg>
				{:else}
					<span>&#10003;</span>
				{/if}
				True Positive
			</button>

			<button
				onclick={(e) => handleLabel('fp', e)}
				disabled={loading || closing || labeled !== null}
				class={[
					'flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
					labeled === 'fp'
						? 'bg-red-700 border-red-600 text-white'
						: labeled === 'tp'
							? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-500 cursor-not-allowed'
							: 'bg-red-900/40 border-red-700 text-red-400 hover:bg-red-900/70 cursor-pointer'
				].join(' ')}
			>
				{#if labeled === 'fp'}
					<svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
						<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
					</svg>
				{:else}
					<span>&#10007;</span>
				{/if}
				False Positive
			</button>

			{#if onclose}
				<button
					onclick={handleClose}
					disabled={loading || closing || labeled !== null}
					class={[
						'col-span-2 flex items-center justify-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border transition-colors',
						labeled
							? 'bg-[var(--mk-border)] border-[var(--mk-border-strong)] text-gray-500 cursor-not-allowed'
							: 'bg-[var(--mk-bg-elevated)] border-[var(--mk-border-strong)] text-gray-300 hover:bg-[var(--mk-bg-hover)] hover:border-violet-500/50 cursor-pointer'
					].join(' ')}
				>
					<span>&#8722;</span>
					{closing ? 'Closing...' : 'Close Case'}
				</button>
			{/if}
		</div>
	{/if}
</div>
