<script lang="ts">
	import { severityTone } from '$lib/theme';
	import type { Severity, TraceGraph, TraceGraphEdge, TraceGraphNode } from '$lib/types';

	const NODE_WIDTH = 292;
	const NODE_HEIGHT = 94;
	const FINDING_HEIGHT = 112;
	const X_GAP = 104;
	const LAYER_COLUMN_GAP = 28;
	const Y_GAP = 24;
	const MAX_LAYER_ROWS = 8;
	const COMPONENT_PAD = 34;
	const COMPONENT_GAP = 64;
	const CANVAS_PAD = 42;
	const TARGET_ROW_WIDTH = 2300;
	const MIN_ZOOM = 0.3;
	const MAX_ZOOM = 2;

	type RouteNode = TraceGraphNode & {
		order: number;
	};

	type PositionedNode = RouteNode & {
		x: number;
		y: number;
		width: number;
		height: number;
		rank: number;
		componentId: string;
	};

	type PositionedEdge = TraceGraphEdge & {
		path: string;
		labelX: number;
		labelY: number;
	};

	type ComponentBox = {
		id: string;
		x: number;
		y: number;
		width: number;
		height: number;
		label: string;
		nodeCount: number;
		findingCount: number;
	};

	let {
		graph,
		variant = 'compact',
		focusedFindingId = null,
		resetSignal = 0,
		onselectnode,
		onlocatenode,
		onauditnode
	}: {
		graph: TraceGraph;
		variant?: 'compact' | 'workspace';
		focusedFindingId?: string | null;
		resetSignal?: number;
		onselectnode?: (node: TraceGraphNode) => void;
		onlocatenode?: (node: TraceGraphNode) => void;
		onauditnode?: (node: TraceGraphNode) => void;
	} = $props();

	let selectedNodeId = $state<string | null>(null);
	let hoveredNodeId = $state<string | null>(null);
	let viewportEl = $state<HTMLDivElement | null>(null);
	let zoom = $state(1);
	let pan = $state({ x: 0, y: 0 });
	let isPanning = $state(false);
	let lastPointer = $state({ x: 0, y: 0 });
	let lastFitSignature = '';
	let lastResetSignal = 0;

	const nodeMap = $derived.by(() => {
		const map = new Map<string, TraceGraphNode>();
		for (const node of graph.nodes) map.set(node.id, node);
		return map;
	});

	const outgoingEdges = $derived.by(() => {
		const map = new Map<string, TraceGraphEdge[]>();
		for (const node of graph.nodes) map.set(node.id, []);
		for (const edge of graph.edges) map.get(edge.source)?.push(edge);
		return map;
	});

	const incomingEdges = $derived.by(() => {
		const map = new Map<string, TraceGraphEdge[]>();
		for (const node of graph.nodes) map.set(node.id, []);
		for (const edge of graph.edges) map.get(edge.target)?.push(edge);
		return map;
	});

	const undirected = $derived.by(() => {
		const map = new Map<string, string[]>();
		for (const node of graph.nodes) map.set(node.id, []);
		for (const edge of graph.edges) {
			map.get(edge.source)?.push(edge.target);
			map.get(edge.target)?.push(edge.source);
		}
		return map;
	});

	const nodes = $derived.by(() => orderNodes(graph.nodes));
	const edgeCount = $derived(graph.edges.length);
	const layout = $derived.by(() => buildLayout(nodes));
	const selectedNode = $derived(layout.nodes.find((node) => node.id === selectedNodeId) ?? null);
	const activeNodeId = $derived(hoveredNodeId ?? selectedNodeId);
	const highlighted = $derived.by(() => collectHighlight(activeNodeId));
	const relatedFindingNodes = $derived.by(() => relatedFindings(selectedNode));
	const layoutSignature = $derived(`${layout.width}:${layout.height}:${layout.nodes.length}:${layout.edges.length}`);
	const transformStyle = $derived(
		`width:${layout.width}px;height:${layout.height}px;transform:translate(${pan.x}px, ${pan.y}px) scale(${zoom});transform-origin:0 0;`
	);

	$effect(() => {
		if (focusedFindingId) {
			const focusedNode = layout.nodes.find((node) => node.meta?.findingId === focusedFindingId);
			if (focusedNode) selectedNodeId = focusedNode.id;
		}
	});

	$effect(() => {
		if (selectedNodeId && layout.nodes.some((node) => node.id === selectedNodeId)) return;
		selectedNodeId = null;
	});

	$effect(() => {
		if (variant !== 'workspace' || !viewportEl || layout.nodes.length === 0) return;
		if (lastFitSignature === layoutSignature) return;
		lastFitSignature = layoutSignature;
		requestAnimationFrame(() => fitToView());
	});

	$effect(() => {
		if (resetSignal === lastResetSignal) return;
		lastResetSignal = resetSignal;
		selectedNodeId = null;
		hoveredNodeId = null;
		if (variant === 'workspace') requestAnimationFrame(() => fitToView());
	});

	function orderNodes(input: TraceGraphNode[]) {
		const visited = new Set<string>();
		const ordered: TraceGraphNode[] = [];
		const starts = input
			.filter((node) => (incomingEdges.get(node.id)?.length ?? 0) === 0)
			.sort(compareNodes);

		function visit(id: string) {
			if (visited.has(id)) return;
			visited.add(id);
			const node = nodeMap.get(id);
			if (node) ordered.push(node);
			for (const edge of outgoingEdges.get(id) ?? []) visit(edge.target);
		}

		for (const start of starts.length > 0 ? starts : input.slice(0, 1)) visit(start.id);
		for (const node of input) {
			if (!visited.has(node.id)) ordered.push(node);
		}

		return ordered.map((node, order): RouteNode => ({ ...node, order }));
	}

	function buildLayout(input: RouteNode[]) {
		const components = findComponents(input).sort(compareComponents);
		const positionedNodes: PositionedNode[] = [];
		const boxes: ComponentBox[] = [];
		let cursorX = CANVAS_PAD;
		let cursorY = CANVAS_PAD;
		let rowHeight = 0;
		let maxWidth = 0;

		components.forEach((component, componentIndex) => {
			const componentLayout = layoutComponent(component, `component-${componentIndex + 1}`);
			if (cursorX > CANVAS_PAD && cursorX + componentLayout.width > TARGET_ROW_WIDTH) {
				cursorX = CANVAS_PAD;
				cursorY += rowHeight + COMPONENT_GAP;
				rowHeight = 0;
			}

			for (const node of componentLayout.nodes) {
				positionedNodes.push({
					...node,
					x: node.x + cursorX,
					y: node.y + cursorY
				});
			}

			boxes.push({
				id: componentLayout.id,
				x: cursorX,
				y: cursorY,
				width: componentLayout.width,
				height: componentLayout.height,
				label: componentLayout.label,
				nodeCount: component.length,
				findingCount: component.filter((node) => node.kind === 'finding').length
			});

			maxWidth = Math.max(maxWidth, cursorX + componentLayout.width + CANVAS_PAD);
			rowHeight = Math.max(rowHeight, componentLayout.height);
			cursorX += componentLayout.width + COMPONENT_GAP;
		});

		const positionedById = new Map(positionedNodes.map((node) => [node.id, node]));
		const positionedEdges = graph.edges.flatMap((edge): PositionedEdge[] => {
			const source = positionedById.get(edge.source);
			const target = positionedById.get(edge.target);
			if (!source || !target) return [];
			const forward = target.x >= source.x;
			const sx = forward ? source.x + source.width : source.x;
			const tx = forward ? target.x : target.x + target.width;
			const sy = source.y + source.height / 2;
			const ty = target.y + target.height / 2;
			const curve = Math.max(54, Math.abs(tx - sx) * 0.42);
			const direction = forward ? 1 : -1;
			return [
				{
					...edge,
					path: `M ${sx} ${sy} C ${sx + curve * direction} ${sy}, ${tx - curve * direction} ${ty}, ${tx} ${ty}`,
					labelX: (sx + tx) / 2,
					labelY: (sy + ty) / 2 - 8
				}
			];
		});

		return {
			nodes: positionedNodes,
			edges: positionedEdges,
			boxes,
			width: Math.max(980, maxWidth),
			height: Math.max(620, cursorY + rowHeight + CANVAS_PAD)
		};
	}

	function findComponents(input: RouteNode[]) {
		const visited = new Set<string>();
		const components: RouteNode[][] = [];
		for (const node of input) {
			if (visited.has(node.id)) continue;
			const stack = [node.id];
			const component: RouteNode[] = [];
			visited.add(node.id);
			while (stack.length > 0) {
				const id = stack.pop();
				if (!id) continue;
				const item = input.find((candidate) => candidate.id === id);
				if (item) component.push(item);
				for (const next of undirected.get(id) ?? []) {
					if (visited.has(next)) continue;
					visited.add(next);
					stack.push(next);
				}
			}
			components.push(component.sort(compareNodes));
		}
		return components;
	}

	function layoutComponent(component: RouteNode[], componentId: string) {
		const componentIds = new Set(component.map((node) => node.id));
		const ranks = computeRanks(component, componentIds);
		const layers = new Map<number, RouteNode[]>();
		for (const node of component) {
			const rank = ranks.get(node.id) ?? 0;
			const layer = layers.get(rank) ?? [];
			layer.push(node);
			layers.set(rank, layer);
		}
		for (const layer of layers.values()) layer.sort(compareNodes);

		const positioned: PositionedNode[] = [];
		let componentHeight = COMPONENT_PAD * 2;
		let componentWidth = COMPONENT_PAD * 2;
		let rankX = COMPONENT_PAD;

		for (const [rank, layer] of Array.from(layers.entries()).sort(([a], [b]) => a - b)) {
			const rowCount = Math.min(MAX_LAYER_ROWS, Math.max(1, layer.length));
			const columnCount = Math.ceil(layer.length / MAX_LAYER_ROWS);
			const rowHeights = Array.from({ length: rowCount }, (_, row) =>
				Math.max(
					...layer
						.filter((_, index) => index % MAX_LAYER_ROWS === row)
						.map((node) => (node.kind === 'finding' ? FINDING_HEIGHT : NODE_HEIGHT)),
					NODE_HEIGHT
				)
			);
			const rowOffsets: number[] = [];
			let y = COMPONENT_PAD;
			for (const height of rowHeights) {
				rowOffsets.push(y);
				y += height + Y_GAP;
			}

			layer.forEach((node, index) => {
				const column = Math.floor(index / MAX_LAYER_ROWS);
				const row = index % MAX_LAYER_ROWS;
				const height = node.kind === 'finding' ? FINDING_HEIGHT : NODE_HEIGHT;
				positioned.push({
					...node,
					x: rankX + column * (NODE_WIDTH + LAYER_COLUMN_GAP),
					y: rowOffsets[row],
					width: NODE_WIDTH,
					height,
					rank,
					componentId
				});
			});

			const layerWidth = columnCount * NODE_WIDTH + Math.max(0, columnCount - 1) * LAYER_COLUMN_GAP;
			const layerHeight = rowOffsets[rowOffsets.length - 1] + rowHeights[rowHeights.length - 1] + COMPONENT_PAD;
			componentHeight = Math.max(componentHeight, layerHeight);
			componentWidth = Math.max(componentWidth, rankX + layerWidth + COMPONENT_PAD);
			rankX += layerWidth + X_GAP;
		}

		return {
			id: componentId,
			label: componentLabel(component),
			nodes: positioned,
			width: componentWidth,
			height: componentHeight
		};
	}

	function computeRanks(component: RouteNode[], componentIds: Set<string>) {
		const ranks = new Map<string, number>();
		const localIncomingCount = new Map<string, number>();
		for (const node of component) localIncomingCount.set(node.id, 0);
		for (const edge of graph.edges) {
			if (componentIds.has(edge.source) && componentIds.has(edge.target)) {
				localIncomingCount.set(edge.target, (localIncomingCount.get(edge.target) ?? 0) + 1);
			}
		}

		const starts = component
			.filter((node) => (localIncomingCount.get(node.id) ?? 0) === 0)
			.sort(compareNodes);
		const queue: string[] = [];
		for (const start of starts.length > 0 ? starts : component.slice(0, 1)) {
			ranks.set(start.id, 0);
			queue.push(start.id);
		}

		let guard = 0;
		while (queue.length > 0 && guard < component.length * Math.max(graph.edges.length, 1) + 1) {
			guard += 1;
			const current = queue.shift();
			if (!current) continue;
			const nextRank = (ranks.get(current) ?? 0) + 1;
			for (const edge of outgoingEdges.get(current) ?? []) {
				if (!componentIds.has(edge.target)) continue;
				if ((ranks.get(edge.target) ?? -1) >= nextRank) continue;
				ranks.set(edge.target, nextRank);
				queue.push(edge.target);
			}
		}

		let fallbackRank = Math.max(0, ...Array.from(ranks.values()));
		for (const node of component) {
			if (ranks.has(node.id)) continue;
			fallbackRank += 1;
			ranks.set(node.id, fallbackRank);
		}
		return ranks;
	}

	function collectHighlight(id: string | null) {
		const nodeIds = new Set<string>();
		const edgeIds = new Set<string>();
		if (!id) return { nodeIds, edgeIds };

		function walk(current: string, direction: 'up' | 'down') {
			if (nodeIds.has(`${direction}:${current}`)) return;
			nodeIds.add(`${direction}:${current}`);
			const edges = direction === 'down' ? outgoingEdges.get(current) : incomingEdges.get(current);
			for (const edge of edges ?? []) {
				edgeIds.add(edge.id);
				const next = direction === 'down' ? edge.target : edge.source;
				walk(next, direction);
			}
		}

		walk(id, 'up');
		walk(id, 'down');
		return {
			nodeIds: new Set(Array.from(nodeIds).map((value) => value.split(':').slice(1).join(':'))),
			edgeIds
		};
	}

	function relatedFindings(node: PositionedNode | null) {
		if (!node) return [];
		const ids = new Set(node.meta?.relatedFindingIds ?? []);
		if (node.meta?.findingId) ids.add(node.meta.findingId);
		return layout.nodes
			.filter((candidate) => candidate.kind === 'finding' && candidate.meta?.findingId && ids.has(candidate.meta.findingId))
			.sort(compareNodes);
	}

	function selectNode(node: TraceGraphNode) {
		selectedNodeId = node.id;
		onselectnode?.(node);
	}

	function focusFinding(node: TraceGraphNode) {
		selectedNodeId = node.id;
		onselectnode?.(node);
		if (node.meta?.findingId) onlocatenode?.(node);
	}

	function locateNode(node: TraceGraphNode) {
		onlocatenode?.(node);
	}

	function auditNode(node: TraceGraphNode) {
		onauditnode?.(node);
	}

	function fitToView() {
		if (!viewportEl || layout.width <= 0 || layout.height <= 0) return;
		const width = viewportEl.clientWidth;
		const height = viewportEl.clientHeight;
		if (width <= 0 || height <= 0) return;
		const nextZoom = clamp(Math.min((width - 72) / layout.width, (height - 72) / layout.height), MIN_ZOOM, 1.1);
		zoom = nextZoom;
		pan = {
			x: Math.max(24, (width - layout.width * nextZoom) / 2),
			y: Math.max(24, (height - layout.height * nextZoom) / 2)
		};
	}

	function zoomBy(delta: number) {
		if (!viewportEl) return;
		const rect = viewportEl.getBoundingClientRect();
		const centerX = rect.width / 2;
		const centerY = rect.height / 2;
		const nextZoom = clamp(zoom + delta, MIN_ZOOM, MAX_ZOOM);
		const graphX = (centerX - pan.x) / zoom;
		const graphY = (centerY - pan.y) / zoom;
		zoom = nextZoom;
		pan = {
			x: centerX - graphX * nextZoom,
			y: centerY - graphY * nextZoom
		};
	}

	function handleWheel(event: WheelEvent) {
		if (!viewportEl) return;
		event.preventDefault();
		const rect = viewportEl.getBoundingClientRect();
		const mouseX = event.clientX - rect.left;
		const mouseY = event.clientY - rect.top;
		const nextZoom = clamp(zoom * (event.deltaY > 0 ? 0.9 : 1.1), MIN_ZOOM, MAX_ZOOM);
		const graphX = (mouseX - pan.x) / zoom;
		const graphY = (mouseY - pan.y) / zoom;
		zoom = nextZoom;
		pan = {
			x: mouseX - graphX * nextZoom,
			y: mouseY - graphY * nextZoom
		};
	}

	function handlePointerDown(event: PointerEvent) {
		const target = event.target as HTMLElement;
		if (target.closest('[data-trace-node], [data-trace-control]')) return;
		isPanning = true;
		lastPointer = { x: event.clientX, y: event.clientY };
		(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
	}

	function handlePointerMove(event: PointerEvent) {
		if (!isPanning) return;
		const dx = event.clientX - lastPointer.x;
		const dy = event.clientY - lastPointer.y;
		lastPointer = { x: event.clientX, y: event.clientY };
		pan = { x: pan.x + dx, y: pan.y + dy };
	}

	function handlePointerUp(event: PointerEvent) {
		isPanning = false;
		const target = event.currentTarget as HTMLElement;
		if (target.hasPointerCapture(event.pointerId)) target.releasePointerCapture(event.pointerId);
	}

	function compareNodes(a: TraceGraphNode, b: TraceGraphNode) {
		return kindOrder(a.kind) - kindOrder(b.kind)
			|| severityOrder(a.meta?.severity) - severityOrder(b.meta?.severity)
			|| (a.line_start ?? 0) - (b.line_start ?? 0)
			|| a.label.localeCompare(b.label);
	}

	function compareComponents(a: RouteNode[], b: RouteNode[]) {
		return componentSeverity(a) - componentSeverity(b)
			|| b.filter((node) => node.kind === 'finding').length - a.filter((node) => node.kind === 'finding').length
			|| b.length - a.length;
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

	function severityOrder(severity: Severity | null | undefined) {
		switch (severity) {
			case 'critical':
				return 0;
			case 'high':
				return 1;
			case 'medium':
				return 2;
			case 'low':
				return 3;
			default:
				return 4;
		}
	}

	function componentSeverity(component: RouteNode[]) {
		return Math.min(...component.map((node) => severityOrder(node.meta?.severity ?? node.meta?.severities?.[0])));
	}

	function componentLabel(component: RouteNode[]) {
		const findingCount = component.filter((node) => node.kind === 'finding').length;
		const source = component.find((node) => node.kind === 'source')?.label;
		return `${findingCount || 1} trace${findingCount === 1 ? '' : 's'}${source ? ` / ${source}` : ''}`;
	}

	function nodeSubtitle(node: TraceGraphNode) {
		const parts: string[] = [];
		if (node.file) parts.push(node.file);
		if (node.line_start != null) {
			parts.push(node.line_end != null && node.line_end > node.line_start ? `L${node.line_start}-${node.line_end}` : `L${node.line_start}`);
		}
		return parts.join(' / ');
	}

	function nodeDimmed(id: string) {
		return Boolean(activeNodeId && !highlighted.nodeIds.has(id));
	}

	function edgeDimmed(id: string) {
		return Boolean(activeNodeId && !highlighted.edgeIds.has(id));
	}

	function nodeClasses(node: TraceGraphNode, active: boolean) {
		const base = active
			? 'ring-2 ring-[var(--mk-brand)] border-[var(--mk-brand-strong)]'
			: 'hover:border-[var(--mk-border-strong)] hover:bg-[var(--mk-bg-hover)]';
		if (node.kind === 'finding' && node.meta?.severity) {
			return `${base} ${severityBorder(node.meta.severity)} bg-[var(--mk-bg-elevated)]`;
		}
		switch (node.kind) {
			case 'source':
				return `${base} border-teal-700/60 bg-teal-950/20`;
			case 'function':
				return `${base} border-blue-700/60 bg-blue-950/20`;
			case 'sink':
				return `${base} border-red-700/65 bg-red-950/20`;
			case 'finding':
				return `${base} border-violet-700/60 bg-violet-950/20`;
			default:
				return `${base} border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]`;
		}
	}

	function kindBadgeClasses(kind: string) {
		switch (kind) {
			case 'source':
				return 'border-teal-700/70 bg-teal-950/40 text-teal-300';
			case 'function':
				return 'border-blue-700/70 bg-blue-950/40 text-blue-300';
			case 'sink':
				return 'border-red-700/70 bg-red-950/40 text-red-300';
			case 'finding':
				return 'border-violet-700/70 bg-violet-950/40 text-violet-300';
			default:
				return 'border-[var(--mk-border)] bg-[var(--mk-bg-panel)] text-[var(--mk-text-muted)]';
		}
	}

	function severityBorder(severity: Severity) {
		switch (severity) {
			case 'critical':
				return 'border-red-600/90';
			case 'high':
				return 'border-orange-600/90';
			case 'medium':
				return 'border-amber-600/90';
			case 'low':
				return 'border-sky-600/90';
		}
	}

	function severityBadgeClasses(severity: Severity | null | undefined) {
		return severity ? severityTone(severity).badge : 'border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] text-[var(--mk-text-muted)]';
	}

	function edgeClasses(edge: PositionedEdge) {
		const dimmed = edgeDimmed(edge.id);
		if (edge.kind === 'reports') return dimmed ? 'stroke-violet-900/25' : 'stroke-violet-400/80';
		return dimmed ? 'stroke-cyan-900/25' : 'stroke-cyan-300/70';
	}

	function clamp(value: number, min: number, max: number) {
		return Math.min(max, Math.max(min, value));
	}
</script>

{#if variant === 'compact'}
	<div class="overflow-hidden rounded border border-[var(--mk-border)] bg-[var(--mk-bg-panel)]">
		<div class="flex items-center justify-between border-b border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-3 py-1.5">
			<span class="text-[11px] font-semibold tracking-wide text-[var(--mk-text-soft)]">Trace Graph</span>
			<span class="font-mono text-[10px] text-[var(--mk-text-muted)]">{nodes.length} nodes / {edgeCount} edges</span>
		</div>
		<div class="flex items-stretch gap-2 overflow-x-auto px-3 py-3">
			{#each nodes as node, index (node.id)}
				<button
					type="button"
					class={['min-w-[9rem] max-w-[14rem] shrink-0 rounded border px-2.5 py-2 text-left transition-colors', nodeClasses(node, selectedNodeId === node.id)].join(' ')}
					title={node.detail ?? node.label}
					onclick={() => selectNode(node)}
				>
					<span class={['mb-1 inline-flex rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider', kindBadgeClasses(node.kind)].join(' ')}>
						{node.kind}
					</span>
					<span class="block truncate text-[11px] font-semibold text-[var(--mk-text)]">{node.label}</span>
					{#if nodeSubtitle(node)}
						<span class="mt-0.5 block truncate font-mono text-[10px] text-[var(--mk-text-muted)]">{nodeSubtitle(node)}</span>
					{/if}
				</button>
				{#if index < nodes.length - 1}
					<div class="flex shrink-0 items-center text-[var(--mk-text-muted)]">
						<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
							<path d="M3 9h11m0 0-4-4m4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
						</svg>
					</div>
				{/if}
			{/each}
		</div>
	</div>
{:else}
	<div class="flex h-full min-h-0 w-full overflow-hidden">
		<div class="flex min-w-0 flex-1 flex-col bg-[var(--mk-bg)]">
			<div class="flex h-10 shrink-0 items-center justify-between border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)] px-3">
				<div class="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.18em] text-[var(--mk-text-muted)]">
					<span>{layout.boxes.length} components</span>
					<span class="text-[var(--mk-border-strong)]">/</span>
					<span>{layout.nodes.length} nodes</span>
					<span class="text-[var(--mk-border-strong)]">/</span>
					<span>{layout.edges.length} edges</span>
				</div>
				<div class="flex items-center gap-1" data-trace-control>
					<button type="button" onclick={() => zoomBy(-0.1)} class="h-7 rounded border border-[var(--mk-border)] px-2 text-xs font-bold text-[var(--mk-text-muted)] hover:border-[var(--mk-border-strong)] hover:text-[var(--mk-text)]">-</button>
					<span class="min-w-12 rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-1 text-center font-mono text-[10px] text-[var(--mk-text-muted)]">{Math.round(zoom * 100)}%</span>
					<button type="button" onclick={() => zoomBy(0.1)} class="h-7 rounded border border-[var(--mk-border)] px-2 text-xs font-bold text-[var(--mk-text-muted)] hover:border-[var(--mk-border-strong)] hover:text-[var(--mk-text)]">+</button>
					<button type="button" onclick={fitToView} class="h-7 rounded border border-[var(--mk-border)] px-2 text-xs font-semibold text-[var(--mk-text-muted)] hover:border-[var(--mk-brand)] hover:text-[var(--mk-text)]">Fit</button>
				</div>
			</div>

			<div
				bind:this={viewportEl}
				class={['relative min-h-0 flex-1 overflow-hidden bg-[var(--mk-bg)]', isPanning ? 'cursor-grabbing' : 'cursor-grab'].join(' ')}
				style="background-image: radial-gradient(circle, rgba(216, 199, 170, 0.08) 1px, transparent 1px); background-size: 22px 22px;"
				role="application"
				aria-label="Trace graph canvas"
				onwheel={handleWheel}
				onpointerdown={handlePointerDown}
				onpointermove={handlePointerMove}
				onpointerup={handlePointerUp}
				onpointercancel={handlePointerUp}
			>
				<div class="absolute left-0 top-0" style={transformStyle}>
					<svg
						class="absolute inset-0 pointer-events-none"
						width={layout.width}
						height={layout.height}
						viewBox={`0 0 ${layout.width} ${layout.height}`}
						aria-hidden="true"
					>
						<defs>
							<marker id="trace-arrow-flow" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="strokeWidth">
								<path d="M 0 0 L 10 5 L 0 10 z" class="fill-cyan-300/70"></path>
							</marker>
							<marker id="trace-arrow-report" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="strokeWidth">
								<path d="M 0 0 L 10 5 L 0 10 z" class="fill-violet-400/80"></path>
							</marker>
							<filter id="trace-edge-glow" x="-50%" y="-50%" width="200%" height="200%">
								<feGaussianBlur stdDeviation="2.4" result="blur" />
								<feMerge>
									<feMergeNode in="blur" />
									<feMergeNode in="SourceGraphic" />
								</feMerge>
							</filter>
						</defs>

						{#each layout.boxes as box (box.id)}
							<rect
								x={box.x}
								y={box.y}
								width={box.width}
								height={box.height}
								rx="10"
								class="fill-[var(--mk-bg-elevated)] stroke-[var(--mk-border)]"
								fill-opacity="0.22"
							/>
							<text x={box.x + 14} y={box.y + 20} class="fill-[var(--mk-text-muted)] text-[10px] font-bold uppercase tracking-[0.18em]">
								{box.label}
							</text>
						{/each}

						{#each layout.edges as edge (edge.id)}
							<path
								d={edge.path}
								fill="none"
								class={edgeClasses(edge)}
								stroke-width={highlighted.edgeIds.has(edge.id) ? 3 : edge.kind === 'reports' ? 2 : 1.5}
								stroke-linecap="round"
								filter={highlighted.edgeIds.has(edge.id) ? 'url(#trace-edge-glow)' : undefined}
								marker-end={edgeDimmed(edge.id) ? undefined : edge.kind === 'reports' ? 'url(#trace-arrow-report)' : 'url(#trace-arrow-flow)'}
							/>
						{/each}
					</svg>

					{#each layout.nodes as node (node.id)}
						<button
							type="button"
							data-trace-node
							onclick={() => selectNode(node)}
							onpointerenter={() => (hoveredNodeId = node.id)}
							onpointerleave={() => (hoveredNodeId = null)}
							ondblclick={() => locateNode(node)}
							class={[
								'absolute flex flex-col gap-1 rounded-md border px-3 py-2 text-left transition-all cursor-pointer shadow-sm backdrop-blur',
								nodeClasses(node, selectedNodeId === node.id),
								nodeDimmed(node.id) ? 'opacity-25' : 'opacity-100'
							].join(' ')}
							style={`left:${node.x}px;top:${node.y}px;width:${node.width}px;min-height:${node.height}px;`}
							title={node.detail ?? node.label}
						>
							<div class="flex items-center justify-between gap-2">
								<span class={['rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider', kindBadgeClasses(node.kind)].join(' ')}>
									{node.kind === 'finding' && node.meta?.ordinal ? `MAKINA-${String(node.meta.ordinal).padStart(3, '0')}` : node.kind}
								</span>
								{#if node.kind === 'finding'}
									<span class={['rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider', severityBadgeClasses(node.meta?.severity)].join(' ')}>
										{node.meta?.severity ?? 'finding'}
									</span>
								{:else}
									<span class="font-mono text-[10px] text-[var(--mk-text-muted)]">{node.rank + 1}.{node.order + 1}</span>
								{/if}
							</div>
							{#if node.kind === 'finding' && node.meta?.cwe}
								<span class="inline-flex w-fit rounded border border-[var(--mk-border)] bg-[var(--mk-bg-panel)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--mk-text-soft)]">{node.meta.cwe}</span>
							{/if}
							<span class="max-h-10 overflow-hidden text-xs font-semibold leading-snug text-[var(--mk-text)]">{node.meta?.message ?? node.label}</span>
							{#if nodeSubtitle(node)}
								<span class="truncate font-mono text-[10px] text-[var(--mk-text-muted)]">{nodeSubtitle(node)}</span>
							{/if}
						</button>
					{/each}
				</div>
			</div>
		</div>

		<aside class="w-80 shrink-0 border-l border-[var(--mk-border)] bg-[var(--mk-bg-panel)]">
			<div class="border-b border-[var(--mk-border)] px-3 py-2">
				<div class="text-[10px] font-bold uppercase tracking-[0.2em] text-[var(--mk-text-muted)]">Inspector</div>
			</div>
			{#if selectedNode}
				<div class="space-y-4 p-3">
					<div>
						<div class="flex flex-wrap items-center gap-1.5">
							<span class={['rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider', kindBadgeClasses(selectedNode.kind)].join(' ')}>
								{selectedNode.kind}
							</span>
							{#if selectedNode.meta?.severity}
								<span class={['rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider', severityBadgeClasses(selectedNode.meta.severity)].join(' ')}>
									{selectedNode.meta.severity}
								</span>
							{/if}
							{#if selectedNode.meta?.cwe}
								<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--mk-text-soft)]">{selectedNode.meta.cwe}</span>
							{/if}
						</div>
						<p class="mt-2 text-sm font-semibold leading-snug text-[var(--mk-text)]">{selectedNode.meta?.message ?? selectedNode.label}</p>
						{#if nodeSubtitle(selectedNode)}
							<p class="mt-1 break-all font-mono text-[11px] text-[var(--mk-text-muted)]">{nodeSubtitle(selectedNode)}</p>
						{/if}
					</div>

					<div class="grid grid-cols-3 gap-2">
						<button
							type="button"
							onclick={() => focusFinding(selectedNode)}
							class="rounded border border-[var(--mk-border)] px-2 py-1.5 text-xs font-semibold text-[var(--mk-text-soft)] transition hover:border-[var(--mk-brand)] hover:text-white"
						>
							{selectedNode.meta?.findingId ? 'Focus finding' : 'Select node'}
						</button>
						<button
							type="button"
							disabled={!selectedNode.meta?.findingId}
							onclick={() => locateNode(selectedNode)}
							class="rounded border border-[var(--mk-border)] px-2 py-1.5 text-xs font-semibold text-[var(--mk-text-soft)] transition hover:border-[var(--mk-brand)] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
						>
							Locate code
						</button>
						<button
							type="button"
							disabled={!selectedNode.meta?.findingId}
							onclick={() => auditNode(selectedNode)}
							class="rounded border border-[var(--mk-border)] px-2 py-1.5 text-xs font-semibold text-[var(--mk-text-soft)] transition hover:border-[var(--mk-brand)] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
						>
							Audit
						</button>
					</div>

					{#if relatedFindingNodes.length > 0}
						<div>
							<div class="mb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-[var(--mk-text-muted)]">Related findings</div>
							<div class="space-y-2">
								{#each relatedFindingNodes as findingNode (findingNode.id)}
									<button
										type="button"
										onclick={() => selectNode(findingNode)}
										class="w-full rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-2 text-left transition hover:border-[var(--mk-border-strong)]"
									>
										<div class="flex items-center gap-1.5">
											<span class="rounded border border-violet-700/70 bg-violet-950/40 px-1.5 py-0.5 font-mono text-[10px] font-bold text-violet-300">
												MAKINA-{String(findingNode.meta?.ordinal ?? 0).padStart(3, '0')}
											</span>
											{#if findingNode.meta?.cwe}
												<span class="font-mono text-[10px] text-[var(--mk-text-muted)]">{findingNode.meta.cwe}</span>
											{/if}
										</div>
										<p class="mt-1 max-h-9 overflow-hidden text-xs font-semibold leading-snug text-[var(--mk-text-soft)]">{findingNode.meta?.message ?? findingNode.label}</p>
									</button>
								{/each}
							</div>
						</div>
					{/if}

					{#if selectedNode.detail}
						<pre class="max-h-[24rem] overflow-auto whitespace-pre-wrap rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-2 font-mono text-[11px] leading-relaxed text-[var(--mk-text-soft)]">{selectedNode.detail}</pre>
					{:else}
						<div class="rounded border border-dashed border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-2 text-xs text-[var(--mk-text-muted)]">
							No node detail available.
						</div>
					{/if}
				</div>
			{:else}
				<div class="space-y-4 p-3">
					<div class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-3">
						<p class="text-sm font-semibold text-[var(--mk-text)]">Graph overview</p>
						<p class="mt-1 text-xs leading-relaxed text-[var(--mk-text-muted)]">Hover a node to highlight its upstream and downstream evidence path. Click a node to inspect code context and related findings.</p>
					</div>
					<div class="grid grid-cols-2 gap-2 text-xs">
						<div class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-2">
							<div class="font-mono text-lg font-bold text-[var(--mk-text)]">{layout.boxes.length}</div>
							<div class="text-[10px] font-bold uppercase tracking-wider text-[var(--mk-text-muted)]">Components</div>
						</div>
						<div class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-2">
							<div class="font-mono text-lg font-bold text-[var(--mk-text)]">{layout.nodes.filter((node) => node.kind === 'finding').length}</div>
							<div class="text-[10px] font-bold uppercase tracking-wider text-[var(--mk-text-muted)]">Findings</div>
						</div>
					</div>
					<button
						type="button"
						onclick={fitToView}
						class="w-full rounded border border-[var(--mk-border)] px-3 py-2 text-xs font-semibold text-[var(--mk-text-soft)] transition hover:border-[var(--mk-brand)] hover:text-white"
					>
						Fit graph to view
					</button>
				</div>
			{/if}
		</aside>
	</div>
{/if}
