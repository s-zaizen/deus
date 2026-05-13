<script lang="ts">
	import type { Finding } from '$lib/types';
	import TraceGraph from './TraceGraph.svelte';
	import { severityTone } from '$lib/theme';

	let {
		findings,
		focusedFindingId = null,
		onselect
	}: {
		findings: Finding[];
		focusedFindingId?: string | null;
		onselect: (id: string) => void;
	} = $props();

	const findingsWithGraph = $derived(findings.filter((f) => f.trace_graph?.nodes?.length));
	const selectedFinding = $derived(findings.find((f) => f.id === focusedFindingId) ?? null);

	$effect(() => {
		if (findings.length === 0 || selectedFinding) return;
		if (findingsWithGraph.length > 0) {
			onselect(findingsWithGraph[0].id);
			return;
		}
		onselect(findings[0].id);
	});

	function handleSelectFinding(id: string) {
		onselect(id);
	}
</script>

<div class="flex h-full w-full">
	<!-- Left navigator -->
	<div class="w-72 shrink-0 flex flex-col border-r border-[var(--mk-border)] bg-[var(--mk-bg-panel)]">
		<div class="px-3 py-2 border-b border-[var(--mk-border)] flex items-center justify-between">
			<span class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Findings</span>
			<span class="text-[10px] text-gray-500 tabular-nums">{findingsWithGraph.length} with trace</span>
		</div>
		<div class="flex-1 overflow-y-auto p-2 space-y-1">
			{#if findings.length === 0}
				<div class="flex flex-col items-center justify-center gap-3 py-10 text-center px-3">
					<svg class="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
					</svg>
					<div class="space-y-0.5">
						<p class="text-sm font-medium text-gray-300">No findings</p>
						<p class="text-xs text-gray-500">Run a scan to populate trace graphs</p>
					</div>
				</div>
			{:else}
				{#each findings as finding (finding.id)}
					{@const tone = severityTone(finding.severity)}
					<button
						class={[
							'w-full text-left rounded border px-2.5 py-2 transition-all',
							finding.id === focusedFindingId
								? 'border-violet-500/60 bg-violet-950/20 ring-1 ring-violet-500/30'
								: 'border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] hover:border-[var(--mk-border-strong)] hover:bg-[var(--mk-bg-hover)]'
						].join(' ')}
						onclick={() => handleSelectFinding(finding.id)}
					>
						<div class="flex items-center gap-1.5 mb-1">
							<span
								class={[
									'text-[9px] font-semibold px-1.5 py-0.5 rounded-full border uppercase tracking-wide shrink-0',
									tone.badge
								].join(' ')}
							>
								{finding.severity}
							</span>
							<span class="text-[10px] font-mono text-gray-400 truncate">{finding.rule_id}</span>
						</div>
						<p class="text-[11px] text-gray-200 leading-snug line-clamp-2">{finding.message}</p>
						{#if finding.trace_graph?.nodes?.length}
							<span class="mt-1 inline-flex items-center text-[10px] text-[var(--mk-text-muted)]">
								<svg class="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
									<path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
								</svg>
								{finding.trace_graph.nodes.length} nodes
							</span>
						{:else}
							<span class="mt-1 inline-flex items-center text-[10px] text-gray-600">
								No trace graph
							</span>
						{/if}
					</button>
				{/each}
			{/if}
		</div>
	</div>

	<!-- Right workspace -->
	<div class="flex-1 min-w-0 flex flex-col bg-[var(--mk-bg)] overflow-hidden">
		{#if !selectedFinding}
			<div class="flex flex-1 items-center justify-center">
				<div class="text-center space-y-3 px-4">
					<svg class="w-10 h-10 mx-auto text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
					</svg>
					<p class="text-sm text-gray-400">Select a finding to view its trace graph</p>
				</div>
			</div>
		{:else if !selectedFinding.trace_graph?.nodes?.length}
			<div class="flex flex-1 items-center justify-center">
				<div class="text-center space-y-3 max-w-sm px-4">
					<svg class="w-10 h-10 mx-auto text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
					</svg>
					<p class="text-sm text-gray-400">No trace evidence available</p>
					<p class="text-xs text-gray-500 leading-relaxed">
						This finding does not have an associated taint graph. Run a scan that includes taint analysis to generate trace data.
					</p>
				</div>
			</div>
		{:else}
			<TraceGraph graph={selectedFinding.trace_graph} variant="workspace" />
		{/if}
	</div>
</div>
