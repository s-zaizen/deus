<script lang="ts">
	import type { Finding, Severity, TraceGraph, TraceGraphNode } from '$lib/types';
	import TraceGraphView from './TraceGraph.svelte';

	let {
		findings,
		focusedFindingId = null,
		onselect,
		onlocate,
		onaudit
	}: {
		findings: Finding[];
		focusedFindingId?: string | null;
		onselect: (id: string) => void;
		onlocate?: (id: string) => void;
		onaudit?: (id: string) => void;
	} = $props();

	type NodeKind = 'source' | 'function' | 'sink' | 'finding';

	const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low'];
	const kindOrder: NodeKind[] = ['source', 'function', 'sink', 'finding'];

	let search = $state('');
	let cweFilter = $state('all');
	let fileFilter = $state('all');
	let severityEnabled = $state<Record<Severity, boolean>>({
		critical: true,
		high: true,
		medium: true,
		low: true
	});
	let kindEnabled = $state<Record<NodeKind, boolean>>({
		source: true,
		function: true,
		sink: true,
		finding: true
	});
	let resetSignal = $state(0);

	const findingsWithGraph = $derived(findings.filter((finding) => finding.trace_graph?.nodes?.length));
	const findingsWithoutGraph = $derived(findings.length - findingsWithGraph.length);
	const combinedGraph = $derived.by(() => combineGraphs(findingsWithGraph));
	const cweOptions = $derived.by(() =>
		Array.from(new Set(findingsWithGraph.map((finding) => finding.cwe).filter(Boolean) as string[])).sort()
	);
	const fileOptions = $derived.by(() => {
		const files = new Set<string>();
		for (const finding of findingsWithGraph) {
			for (const node of finding.trace_graph?.nodes ?? []) {
				if (node.file) files.add(node.file);
			}
		}
		return Array.from(files).sort();
	});
	const filteredFindingIds = $derived.by(() => {
		const query = search.trim().toLowerCase();
		const ids = new Set<string>();
		for (const finding of findingsWithGraph) {
			if (!severityEnabled[finding.severity]) continue;
			if (cweFilter !== 'all' && finding.cwe !== cweFilter) continue;
			if (fileFilter !== 'all' && !(finding.trace_graph?.nodes ?? []).some((node) => node.file === fileFilter)) continue;
			if (query && !findingMatchesQuery(finding, query)) continue;
			ids.add(finding.id);
		}
		return ids;
	});
	const filteredGraph = $derived.by(() => filterGraph(combinedGraph, filteredFindingIds));

	function combineGraphs(items: Finding[]): TraceGraph {
		const nodes = new Map<string, TraceGraphNode>();
		const edges = new Map<string, TraceGraph['edges'][number]>();

		items.forEach((finding, index) => {
			const graph = finding.trace_graph;
			if (!graph) return;
			const localNodes = new Map(graph.nodes.map((node) => [node.id, node]));

			function mappedId(id: string) {
				const node = localNodes.get(id);
				if (node?.kind === 'finding') return `${id}:${finding.id}`;
				return id;
			}

			for (const node of graph.nodes) {
				const id = mappedId(node.id);
				const existing = nodes.get(id);
				const ordinal = index + 1;
				const detail =
					node.kind === 'finding'
						? `MAKINA-${String(ordinal).padStart(3, '0')} ${finding.cwe ?? 'CWE-unknown'} ${finding.message}\n\n${node.detail ?? ''}`.trim()
						: node.detail;
				const nodeMeta = {
					...(node.meta ?? {}),
					relatedFindingIds: [finding.id],
					severities: [finding.severity],
					cwes: finding.cwe ? [finding.cwe] : [],
					...(node.kind === 'finding'
						? {
								findingId: finding.id,
								severity: finding.severity,
								cwe: finding.cwe,
								message: finding.message,
								ruleId: finding.rule_id,
								source: finding.source,
								confidence: finding.confidence,
								ordinal
							}
						: {})
				};

				if (!existing) {
					nodes.set(id, {
						...node,
						id,
						detail,
						meta: nodeMeta
					});
					continue;
				}

				const mergedDetail = [existing.detail, detail]
					.filter(Boolean)
					.filter((value, valueIndex, list) => list.indexOf(value) === valueIndex)
					.join('\n\n');
				const relatedFindingIds = mergeList(existing.meta?.relatedFindingIds, [finding.id]);
				const severities = mergeList(existing.meta?.severities, [finding.severity]);
				const cwes = mergeList(existing.meta?.cwes, finding.cwe ? [finding.cwe] : []);
				nodes.set(id, {
					...existing,
					file: existing.file ?? node.file,
					line_start: existing.line_start ?? node.line_start,
					line_end: existing.line_end ?? node.line_end,
					detail: mergedDetail || existing.detail,
					meta: {
						...(existing.meta ?? {}),
						relatedFindingIds,
						severities,
						cwes
					}
				});
			}

			for (const edge of graph.edges) {
				const source = mappedId(edge.source);
				const target = mappedId(edge.target);
				const id = `${source}->${target}:${edge.kind}`;
				if (edges.has(id)) continue;
				edges.set(id, {
					...edge,
					id,
					source,
					target
				});
			}
		});

		return {
			nodes: Array.from(nodes.values()),
			edges: Array.from(edges.values())
		};
	}

	function filterGraph(graph: TraceGraph, visibleFindingIds: Set<string>): TraceGraph {
		const visibleNodes = graph.nodes.filter((node) => {
			if (!kindEnabled[kindKey(node.kind)]) return false;
			if (node.kind === 'finding') {
				const findingId = node.meta?.findingId;
				return Boolean(findingId && visibleFindingIds.has(findingId));
			}
			return (node.meta?.relatedFindingIds ?? []).some((id) => visibleFindingIds.has(id));
		});
		const nodeIds = new Set(visibleNodes.map((node) => node.id));
		return {
			nodes: visibleNodes,
			edges: graph.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
		};
	}

	function findingMatchesQuery(finding: Finding, query: string) {
		const haystack = [
			finding.rule_id,
			finding.cwe,
			finding.message,
			finding.source,
			finding.code_snippet,
			...(finding.trace_graph?.nodes ?? []).flatMap((node) => [node.label, node.file, node.detail])
		]
			.filter(Boolean)
			.join('\n')
			.toLowerCase();
		return haystack.includes(query);
	}

	function mergeList<T>(left: T[] | undefined, right: T[]) {
		return Array.from(new Set([...(left ?? []), ...right]));
	}

	function kindKey(kind: string): NodeKind {
		return kindOrder.includes(kind as NodeKind) ? (kind as NodeKind) : 'function';
	}

	function toggleSeverity(severity: Severity) {
		severityEnabled = {
			...severityEnabled,
			[severity]: !severityEnabled[severity]
		};
	}

	function toggleKind(kind: NodeKind) {
		kindEnabled = {
			...kindEnabled,
			[kind]: !kindEnabled[kind]
		};
	}

	function resetFilters() {
		search = '';
		cweFilter = 'all';
		fileFilter = 'all';
		severityEnabled = {
			critical: true,
			high: true,
			medium: true,
			low: true
		};
		kindEnabled = {
			source: true,
			function: true,
			sink: true,
			finding: true
		};
		resetSignal += 1;
	}

	function handleNodeSelect(node: TraceGraphNode) {
		const findingId = node.meta?.findingId;
		if (findingId) onselect(findingId);
	}

	function handleNodeLocate(node: TraceGraphNode) {
		const findingId = node.meta?.findingId;
		if (findingId) onlocate?.(findingId);
	}

	function handleNodeAudit(node: TraceGraphNode) {
		const findingId = node.meta?.findingId;
		if (findingId) onaudit?.(findingId);
	}
</script>

<div class="flex h-full min-h-0 w-full flex-col bg-[var(--mk-bg)]">
	<div class="shrink-0 border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)]">
		<div class="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
			<div>
				<div class="text-[10px] font-bold uppercase tracking-[0.24em] text-[var(--mk-text-muted)]">Trace Graph</div>
				<div class="mt-1 text-sm font-semibold text-[var(--mk-text)]">Combined call graph for this case</div>
			</div>
			<div class="flex flex-wrap items-center gap-2 font-mono text-[10px] text-[var(--mk-text-muted)]">
				<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-1">{findings.length} findings</span>
				<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-1">{filteredFindingIds.size}/{findingsWithGraph.length} traced</span>
				<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-1">{findingsWithoutGraph} without trace</span>
				<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-1">{filteredGraph.nodes.length}/{combinedGraph.nodes.length} nodes</span>
			</div>
		</div>

		<div class="flex flex-wrap items-center gap-2 border-t border-[var(--mk-border)] px-4 py-2">
			<label class="min-w-[14rem] flex-1">
				<span class="sr-only">Search trace graph</span>
				<input
					bind:value={search}
					placeholder="Search function, file, CWE..."
					class="h-8 w-full rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-3 text-xs text-[var(--mk-text)] outline-none transition focus:border-[var(--mk-brand)]"
				/>
			</label>
			<select
				bind:value={cweFilter}
				class="h-8 rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 text-xs font-semibold text-[var(--mk-text-soft)] outline-none transition focus:border-[var(--mk-brand)]"
				aria-label="Filter by CWE"
			>
				<option value="all">All CWEs</option>
				{#each cweOptions as cwe}
					<option value={cwe}>{cwe}</option>
				{/each}
			</select>
			<select
				bind:value={fileFilter}
				class="h-8 max-w-[16rem] rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 text-xs font-semibold text-[var(--mk-text-soft)] outline-none transition focus:border-[var(--mk-brand)]"
				aria-label="Filter by file"
			>
				<option value="all">All files</option>
				{#each fileOptions as file}
					<option value={file}>{file}</option>
				{/each}
			</select>

			<div class="flex items-center gap-1 rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-0.5">
				{#each severityOrder as severity}
					<button
						type="button"
						onclick={() => toggleSeverity(severity)}
						class={[
							'rounded px-2 py-1 text-[10px] font-bold uppercase tracking-wider transition',
							severityEnabled[severity]
								? 'bg-[var(--mk-brand)] text-white'
								: 'text-[var(--mk-text-muted)] hover:bg-[var(--mk-bg-hover)] hover:text-[var(--mk-text)]'
						].join(' ')}
					>
						{severity}
					</button>
				{/each}
			</div>

			<div class="flex items-center gap-1 rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-0.5">
				{#each kindOrder as kind}
					<button
						type="button"
						onclick={() => toggleKind(kind)}
						class={[
							'rounded px-2 py-1 text-[10px] font-bold uppercase tracking-wider transition',
							kindEnabled[kind]
								? 'bg-[var(--mk-bg-hover)] text-[var(--mk-text)]'
								: 'text-[var(--mk-text-muted)] hover:bg-[var(--mk-bg-hover)] hover:text-[var(--mk-text)]'
						].join(' ')}
					>
						{kind}
					</button>
				{/each}
			</div>

			<button
				type="button"
				onclick={resetFilters}
				class="h-8 rounded border border-[var(--mk-border)] px-3 text-xs font-semibold text-[var(--mk-text-muted)] transition hover:border-[var(--mk-border-strong)] hover:text-[var(--mk-text)]"
			>
				Reset
			</button>
		</div>
	</div>

	<div class="min-h-0 flex-1">
		{#if findings.length === 0}
			<div class="flex h-full items-center justify-center">
				<div class="max-w-sm text-center">
					<svg class="mx-auto mb-3 h-9 w-9 text-[var(--mk-text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
					</svg>
					<p class="text-sm font-semibold text-[var(--mk-text)]">No findings</p>
					<p class="mt-1 text-xs text-[var(--mk-text-muted)]">Run a scan to populate trace graphs.</p>
				</div>
			</div>
		{:else if combinedGraph.nodes.length === 0}
			<div class="flex h-full items-center justify-center">
				<div class="max-w-sm text-center">
					<svg class="mx-auto mb-3 h-9 w-9 text-[var(--mk-text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
						<path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
					</svg>
					<p class="text-sm font-semibold text-[var(--mk-text)]">No trace graph evidence</p>
					<p class="mt-1 text-xs text-[var(--mk-text-muted)]">The current findings do not include source-to-sink graph data.</p>
				</div>
			</div>
		{:else if filteredGraph.nodes.length === 0}
			<div class="flex h-full items-center justify-center">
				<div class="max-w-sm text-center">
					<p class="text-sm font-semibold text-[var(--mk-text)]">No matching trace nodes</p>
					<p class="mt-1 text-xs text-[var(--mk-text-muted)]">Relax the filters to bring trace evidence back into scope.</p>
					<button
						type="button"
						onclick={resetFilters}
						class="mt-4 rounded border border-[var(--mk-border-strong)] px-3 py-1.5 text-xs font-semibold text-[var(--mk-text-soft)] transition hover:border-[var(--mk-brand)] hover:text-white"
					>
						Reset filters
					</button>
				</div>
			</div>
		{:else}
			<TraceGraphView
				graph={filteredGraph}
				variant="workspace"
				{focusedFindingId}
				{resetSignal}
				onselectnode={handleNodeSelect}
				onlocatenode={handleNodeLocate}
				onauditnode={handleNodeAudit}
			/>
		{/if}
	</div>
</div>
