<script lang="ts">
	import type { TraceGraph, TraceGraphEdge, TraceGraphNode } from '$lib/types';

	const NODE_WIDTH = 240;
	const NODE_HEIGHT = 94;
	const X_GAP = 156;
	const Y_GAP = 48;
	const PADDING_X = 48;
	const PADDING_Y = 44;

	type PositionedNode = TraceGraphNode & {
		x: number;
		y: number;
		width: number;
		height: number;
		rank: number;
		order: number;
	};

	type PositionedEdge = TraceGraphEdge & {
		path: string;
		labelX: number;
		labelY: number;
		sourceNode: PositionedNode;
		targetNode: PositionedNode;
	};

	let {
		graph,
		variant = 'compact',
		onselectnode
	}: {
		graph: TraceGraph;
		variant?: 'compact' | 'workspace';
		onselectnode?: (node: TraceGraphNode) => void;
	} = $props();

	const nodeMap = $derived.by(() => {
		const map = new Map<string, TraceGraphNode>();
		for (const node of graph.nodes) {
			map.set(node.id, node);
		}
		return map;
	});

	const adjacency = $derived.by(() => {
		const map = new Map<string, string[]>();
		for (const n of graph.nodes) map.set(n.id, []);
		for (const e of graph.edges) {
			const list = map.get(e.source);
			if (list) list.push(e.target);
		}
		return map;
	});

	const inDegree = $derived.by(() => {
		const deg = new Map<string, number>();
		for (const n of graph.nodes) deg.set(n.id, 0);
		for (const e of graph.edges) {
			deg.set(e.target, (deg.get(e.target) ?? 0) + 1);
		}
		return deg;
	});

	const nodes = $derived.by(() => {
		const visited = new Set<string>();
		const result: TraceGraphNode[] = [];

		const starts = Array.from(inDegree.entries())
			.filter(([_, d]) => d === 0)
			.map(([id]) => id)
			.sort((a, b) => {
				const ka = nodeMap.get(a)?.kind ?? '';
				const kb = nodeMap.get(b)?.kind ?? '';
				if (ka === 'source' && kb !== 'source') return -1;
				if (kb === 'source' && ka !== 'source') return 1;
				return 0;
			});

		function dfs(id: string) {
			if (visited.has(id)) return;
			visited.add(id);
			const node = nodeMap.get(id);
			if (node) result.push(node);
			for (const next of adjacency.get(id) ?? []) {
				dfs(next);
			}
		}

		for (const s of starts) dfs(s);

		for (const n of graph.nodes) {
			if (!visited.has(n.id)) result.push(n);
		}

		return result;
	});

	const edgeCount = $derived(graph.edges.length);

	const edgeSet = $derived.by(() => {
		const set = new Set<string>();
		for (const e of graph.edges) {
			set.add(edgeKey(e.source, e.target));
		}
		return set;
	});

	const layout = $derived.by(() => {
		const ranks = new Map<string, number>();
		const starts = nodes.filter((node) => (inDegree.get(node.id) ?? 0) === 0);
		const queue: string[] = [];

		for (const start of starts.length > 0 ? starts : nodes.slice(0, 1)) {
			ranks.set(start.id, 0);
			queue.push(start.id);
		}

		let guard = 0;
		while (queue.length > 0 && guard < graph.nodes.length * Math.max(graph.edges.length, 1) + 1) {
			guard += 1;
			const current = queue.shift();
			if (!current) continue;
			const nextRank = (ranks.get(current) ?? 0) + 1;
			for (const target of adjacency.get(current) ?? []) {
				if ((ranks.get(target) ?? -1) >= nextRank) continue;
				ranks.set(target, nextRank);
				queue.push(target);
			}
		}

		for (const node of nodes) {
			if (!ranks.has(node.id)) ranks.set(node.id, ranks.size === 0 ? 0 : Math.max(...ranks.values()) + 1);
		}

		const layers = new Map<number, TraceGraphNode[]>();
		for (const node of nodes) {
			const rank = ranks.get(node.id) ?? 0;
			const layer = layers.get(rank) ?? [];
			layer.push(node);
			layers.set(rank, layer);
		}

		for (const layer of layers.values()) {
			layer.sort((a, b) => {
				const kindDelta = kindOrder(a.kind) - kindOrder(b.kind);
				if (kindDelta !== 0) return kindDelta;
				return (a.line_start ?? 0) - (b.line_start ?? 0);
			});
		}

		const positionedNodes: PositionedNode[] = [];
		for (const [rank, layer] of Array.from(layers.entries()).sort(([a], [b]) => a - b)) {
			layer.forEach((node, order) => {
				positionedNodes.push({
					...node,
					x: PADDING_X + rank * (NODE_WIDTH + X_GAP),
					y: PADDING_Y + order * (NODE_HEIGHT + Y_GAP),
					width: NODE_WIDTH,
					height: NODE_HEIGHT,
					rank,
					order
				});
			});
		}

		const positionedById = new Map(positionedNodes.map((node) => [node.id, node]));
		const positionedEdges: PositionedEdge[] = graph.edges.flatMap((edge) => {
			const sourceNode = positionedById.get(edge.source);
			const targetNode = positionedById.get(edge.target);
			if (!sourceNode || !targetNode) return [];
			const sx = sourceNode.x + sourceNode.width;
			const sy = sourceNode.y + sourceNode.height / 2;
			const tx = targetNode.x;
			const ty = targetNode.y + targetNode.height / 2;
			const curve = Math.max(80, Math.abs(tx - sx) * 0.48);
			return [{
				...edge,
				sourceNode,
				targetNode,
				path: `M ${sx} ${sy} C ${sx + curve} ${sy}, ${tx - curve} ${ty}, ${tx} ${ty}`,
				labelX: (sx + tx) / 2,
				labelY: (sy + ty) / 2 - 10
			}];
		});

		const maxRank = Math.max(0, ...Array.from(layers.keys()));
		const maxLayerSize = Math.max(1, ...Array.from(layers.values()).map((layer) => layer.length));
		return {
			nodes: positionedNodes,
			edges: positionedEdges,
			width: Math.max(900, PADDING_X * 2 + (maxRank + 1) * NODE_WIDTH + maxRank * X_GAP),
			height: Math.max(520, PADDING_Y * 2 + maxLayerSize * NODE_HEIGHT + (maxLayerSize - 1) * Y_GAP)
		};
	});

	let selectedNodeId = $state<string | null>(null);

	const selectedNode = $derived(graph.nodes.find((n) => n.id === selectedNodeId) ?? null);

	$effect(() => {
		if (variant !== 'workspace') return;
		if (selectedNodeId && graph.nodes.some((n) => n.id === selectedNodeId)) return;
		selectedNodeId = graph.nodes[0]?.id ?? null;
	});

	function edgeKey(source: string, target: string) {
		return `${source}->${target}`;
	}

	function handleNodeClick(node: TraceGraphNode) {
		selectedNodeId = node.id;
		onselectnode?.(node);
	}

	function kindOrder(kind: string) {
		switch (kind) {
			case 'source':
				return 0;
			case 'function':
				return 1;
			case 'sink':
				return 2;
			case 'finding':
				return 3;
			default:
				return 4;
		}
	}

	function kindClasses(kind: string) {
		switch (kind) {
			case 'source':
				return 'border-teal-800/60 bg-teal-950/30 text-teal-300';
			case 'function':
				return 'border-blue-800/60 bg-blue-950/30 text-blue-300';
			case 'sink':
				return 'border-red-800/60 bg-red-950/30 text-red-300';
			case 'finding':
				return 'border-violet-800/60 bg-violet-950/30 text-violet-300';
			default:
				return 'border-gray-700/60 bg-gray-900/40 text-gray-300';
		}
	}

	function kindBadgeClasses(kind: string) {
		switch (kind) {
			case 'source':
				return 'bg-teal-900/60 text-teal-300 border-teal-800/60';
			case 'function':
				return 'bg-blue-900/60 text-blue-300 border-blue-800/60';
			case 'sink':
				return 'bg-red-900/60 text-red-300 border-red-800/60';
			case 'finding':
				return 'bg-violet-900/60 text-violet-300 border-violet-800/60';
			default:
				return 'bg-gray-800 text-gray-300 border-gray-700';
		}
	}

	function edgeClasses(kind: string) {
		switch (kind) {
			case 'reports':
				return 'stroke-violet-400/75';
			case 'flows_to':
				return 'stroke-cyan-300/65';
			default:
				return 'stroke-gray-500/55';
		}
	}

	function nodeSubtitle(n: TraceGraphNode) {
		const parts: string[] = [];
		if (n.file) parts.push(n.file);
		if (n.line_start != null) {
			if (n.line_end != null && n.line_end > n.line_start) {
				parts.push(`L${n.line_start}-${n.line_end}`);
			} else {
				parts.push(`L${n.line_start}`);
			}
		}
		return parts.join(' / ');
	}
</script>

{#if variant === 'compact'}
	<div class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-panel)] overflow-hidden">
		<!-- Header -->
		<div class="flex items-center justify-between px-3 py-1.5 border-b border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]">
			<span class="text-[11px] font-semibold text-[var(--mk-text-soft)] tracking-wide">Trace Graph</span>
			<span class="text-[10px] text-[var(--mk-text-muted)] tabular-nums">{nodes.length} nodes / {edgeCount} edges</span>
		</div>

		<!-- Flow -->
		<div class="flex items-center gap-1 px-3 py-3 overflow-x-auto">
			{#each nodes as node, i (node.id)}
				<div class="flex items-center gap-1 shrink-0">
					<!-- Node card -->
					<div
						class={[
							'relative flex flex-col gap-0.5 min-w-[8rem] max-w-[14rem] rounded border px-2.5 py-2 transition-colors',
							kindClasses(node.kind)
						].join(' ')}
						title={node.detail ?? node.label}
					>
						<span
							class={[
								'inline-flex self-start text-[9px] font-bold uppercase tracking-wider px-1 py-0.5 rounded border leading-none',
								kindBadgeClasses(node.kind)
							].join(' ')}
						>
							{node.kind}
						</span>
						<span class="text-[11px] font-medium leading-snug truncate">{node.label}</span>
						{#if nodeSubtitle(node)}
							<span class="text-[10px] text-[var(--mk-text-muted)] truncate">{nodeSubtitle(node)}</span>
						{/if}
					</div>

					{#if i < nodes.length - 1 && edgeSet.has(edgeKey(node.id, nodes[i + 1].id))}
						<div class="shrink-0 px-0.5">
							<svg width="16" height="16" viewBox="0 0 16 16" fill="none" class="text-[var(--mk-text-muted)]">
								<path d="M3 8H13M13 8L9 4M13 8L9 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
							</svg>
						</div>
					{/if}
				</div>
			{/each}
		</div>
	</div>
{:else}
	<div class="flex flex-col h-full overflow-hidden">
		<!-- Header -->
		<div class="flex items-center justify-between px-4 py-2 border-b border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] shrink-0">
			<div class="flex items-center gap-3">
				<span class="text-xs font-semibold text-[var(--mk-text-soft)] tracking-wide">Call Graph</span>
				<div class="hidden items-center gap-2 text-[10px] text-[var(--mk-text-muted)] md:flex">
					<span class="inline-flex items-center gap-1">
						<span class="h-2 w-2 rounded-full bg-teal-400/80"></span>
						Source
					</span>
					<span class="inline-flex items-center gap-1">
						<span class="h-2 w-2 rounded-full bg-blue-400/80"></span>
						Function
					</span>
					<span class="inline-flex items-center gap-1">
						<span class="h-2 w-2 rounded-full bg-red-400/80"></span>
						Sink
					</span>
					<span class="inline-flex items-center gap-1">
						<span class="h-2 w-2 rounded-full bg-violet-400/80"></span>
						Finding
					</span>
				</div>
			</div>
			<span class="text-[11px] text-[var(--mk-text-muted)] tabular-nums">{nodes.length} nodes / {edgeCount} edges</span>
		</div>

		<div class="flex flex-1 min-h-0">
			<!-- Graph canvas -->
			<div class="flex-1 overflow-auto bg-[var(--mk-bg)] bg-[linear-gradient(rgba(148,163,184,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.035)_1px,transparent_1px)] bg-[size:28px_28px]">
				<div class="relative" style={`width:${layout.width}px;height:${layout.height}px;`}>
					<svg
						class="absolute inset-0 pointer-events-none"
						width={layout.width}
						height={layout.height}
						viewBox={`0 0 ${layout.width} ${layout.height}`}
						aria-hidden="true"
					>
						<defs>
							<marker id="trace-arrow-flow" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="strokeWidth">
								<path d="M 0 0 L 10 5 L 0 10 z" class="fill-cyan-300/65"></path>
							</marker>
							<marker id="trace-arrow-report" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="strokeWidth">
								<path d="M 0 0 L 10 5 L 0 10 z" class="fill-violet-400/75"></path>
							</marker>
						</defs>

						{#each layout.edges as edge (edge.id)}
							<path
								d={edge.path}
								fill="none"
								class={edgeClasses(edge.kind)}
								stroke-width="2"
								stroke-linecap="round"
								marker-end={edge.kind === 'reports' ? 'url(#trace-arrow-report)' : 'url(#trace-arrow-flow)'}
							/>
							{#if edge.label}
								<text
									x={edge.labelX}
									y={edge.labelY}
									text-anchor="middle"
									class="fill-[var(--mk-text-muted)] text-[10px] uppercase tracking-wider"
								>
									{edge.label}
								</text>
							{/if}
						{/each}
					</svg>

					{#each layout.nodes as node (node.id)}
						<button
							type="button"
							onclick={() => handleNodeClick(node)}
							onkeydown={(e) => e.key === 'Enter' && handleNodeClick(node)}
							class={[
								'absolute flex flex-col gap-1.5 rounded-lg border px-3.5 py-3 text-left transition-all cursor-pointer shadow-[0_12px_30px_rgba(0,0,0,0.22)] backdrop-blur',
								kindClasses(node.kind),
								selectedNodeId === node.id
									? 'ring-2 ring-violet-500/70 shadow-[0_0_24px_rgba(139,92,246,0.2)]'
									: 'hover:ring-1 hover:ring-violet-500/35 hover:-translate-y-0.5'
							].join(' ')}
							style={`left:${node.x}px;top:${node.y}px;width:${node.width}px;min-height:${node.height}px;`}
							title={node.detail ?? node.label}
						>
							<div class="flex items-start justify-between gap-2">
								<span
									class={[
										'inline-flex text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border leading-none',
										kindBadgeClasses(node.kind)
									].join(' ')}
								>
									{node.kind}
								</span>
								<span class="font-mono text-[10px] text-[var(--mk-text-muted)]">#{node.rank + 1}.{node.order + 1}</span>
							</div>
							<span class="text-xs font-semibold leading-snug text-[var(--mk-text)]">{node.label}</span>
							{#if nodeSubtitle(node)}
								<span class="text-[11px] text-[var(--mk-text-muted)] truncate">{nodeSubtitle(node)}</span>
							{/if}
						</button>
					{/each}
				</div>
			</div>

			<!-- Details sidebar -->
			{#if selectedNode}
				<div class="w-64 shrink-0 border-l border-[var(--mk-border)] bg-[var(--mk-bg-panel)] flex flex-col overflow-hidden">
					<div class="px-3 py-2 border-b border-[var(--mk-border)] shrink-0">
						<span class="text-[10px] font-bold uppercase tracking-wider text-gray-500">Node Details</span>
					</div>
					<div class="flex-1 overflow-y-auto p-3 space-y-3">
						<div>
							<span class="text-[10px] uppercase tracking-wider text-gray-500 block mb-1">Kind</span>
							<span
								class={[
									'inline-flex text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border leading-none',
									kindBadgeClasses(selectedNode.kind)
								].join(' ')}
							>
								{selectedNode.kind}
							</span>
						</div>
						<div>
							<span class="text-[10px] uppercase tracking-wider text-gray-500 block mb-1">Label</span>
							<p class="text-xs text-gray-200 leading-snug">{selectedNode.label}</p>
						</div>
						{#if selectedNode.file}
							<div>
								<span class="text-[10px] uppercase tracking-wider text-gray-500 block mb-1">File</span>
								<p class="text-[11px] text-gray-300 font-mono break-all leading-snug">{selectedNode.file}</p>
							</div>
						{/if}
						{#if selectedNode.line_start != null}
							<div>
								<span class="text-[10px] uppercase tracking-wider text-gray-500 block mb-1">Line</span>
								<p class="text-[11px] text-gray-300 font-mono leading-snug">
									{selectedNode.line_start}{selectedNode.line_end != null && selectedNode.line_end > selectedNode.line_start ? `-${selectedNode.line_end}` : ''}
								</p>
							</div>
						{/if}
						{#if selectedNode.detail}
							<div>
								<span class="text-[10px] uppercase tracking-wider text-gray-500 block mb-1">Detail</span>
								<p class="text-[11px] text-gray-300 leading-relaxed">{selectedNode.detail}</p>
							</div>
						{/if}
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}
