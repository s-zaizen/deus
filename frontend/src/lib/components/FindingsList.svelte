<script lang="ts">
	import FindingCard from '$lib/components/FindingCard.svelte';
	import { PUBLIC_MODE } from '$lib/flags';
	import type { Finding, Label, Language } from '$lib/types';

	let {
		error = null,
		findings,
		scanning,
		scanCompleted = false,
		resultsStale = false,
		language,
		focusedFindingId = null,
		onlabel,
		onclose,
		onfocus
	}: {
		error?: string | null;
		findings: Finding[];
		scanning: boolean;
		scanCompleted?: boolean;
		resultsStale?: boolean;
		language: Language;
		focusedFindingId?: string | null;
		onlabel: (id: string, label: Label) => Promise<void>;
		onclose?: (id: string) => Promise<void> | void;
		onfocus: (id: string) => void;
	} = $props();

	const emptyTitle = $derived(
		scanning ? 'Scanning...' : scanCompleted ? 'No findings found' : 'No findings'
	);
	const emptyDetail = $derived(
		scanning
			? 'Analyzing the current code'
			: scanCompleted
				? 'The analyzer finished without reportable issues'
				: 'Run a scan to analyze this code'
	);
</script>

<div class="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto p-3">
	{#if error}
		<div class="mb-2 rounded-lg border border-red-800 bg-red-900/40 p-3 text-sm text-red-300">
			{error}
		</div>
	{/if}

	{#if resultsStale && findings.length > 0}
		<div class="rounded-lg border border-yellow-800/80 bg-yellow-950/40 p-3 text-xs leading-relaxed text-yellow-200">
			Code changed after this scan. Run Scan again before sending these findings to Verify.
		</div>
	{/if}

	{#if PUBLIC_MODE && findings.length > 0}
		<div class="rounded-lg border border-amber-900/70 bg-amber-950/20 p-3 text-xs leading-relaxed text-amber-100/80">
			Public demo mode is read-only. TP/FP labels and case closing are disabled.
		</div>
	{/if}

	{#if findings.length === 0 && !error}
		<div class="flex flex-col items-center justify-center gap-3 py-10 text-center" aria-live="polite">
			<div class="flex h-12 w-12 items-center justify-center rounded-xl border border-dashed border-gray-700/60 bg-gray-900">
				{#if scanning}
					<svg class="h-6 w-6 animate-spin text-green-400" fill="none" viewBox="0 0 24 24">
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
						<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
					</svg>
				{:else}
					<svg class="h-6 w-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
					</svg>
				{/if}
			</div>
			<div class="space-y-0.5">
				<p class="text-sm font-medium text-gray-300">{emptyTitle}</p>
				<p class="text-xs text-gray-500">{emptyDetail}</p>
			</div>
		</div>
	{/if}

	{#each findings as finding (finding.id)}
		<div class={resultsStale ? 'opacity-60' : ''}>
			<FindingCard
				{finding}
				{language}
				{onlabel}
				{onclose}
				onfocus={() => onfocus(finding.id)}
				focused={finding.id === focusedFindingId}
				readonly={resultsStale || PUBLIC_MODE}
			/>
		</div>
	{/each}
</div>
