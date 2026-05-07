<script lang="ts">
	import type { Stats } from '$lib/types';

	let { stats }: { stats: Stats | null } = $props();

	const stageColors: Record<string, string> = {
		bootstrapping: 'text-gray-500',
		learning: 'text-blue-400',
		refining: 'text-indigo-400',
		mature: 'text-emerald-400'
	};

	const stageColor = $derived(stageColors[stats?.model_stage ?? ''] ?? 'text-gray-400');
</script>

{#if !stats}
	<div class="h-9 bg-gray-900 border-t border-gray-700"></div>
{:else}
	<div class="h-9 bg-gray-900 border-t border-gray-700 flex items-center px-4 gap-4 text-sm">
		<div class="flex items-center gap-1.5">
			<span class="text-gray-600 text-[10px] uppercase tracking-wider font-semibold">Labels</span>
			<span class="text-gray-200 font-semibold tabular-nums">{stats.total_labels}</span>
		</div>
		<span class="text-gray-700">|</span>
		<div class="flex items-center gap-3">
			<span class="flex items-center gap-1">
				<span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
				<span class="text-gray-600 text-[10px] uppercase tracking-wider font-semibold">TP</span>
				<span class="text-green-400 font-semibold tabular-nums">{stats.tp_count}</span>
			</span>
			<span class="flex items-center gap-1">
				<span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>
				<span class="text-gray-600 text-[10px] uppercase tracking-wider font-semibold">FP</span>
				<span class="text-red-400 font-semibold tabular-nums">{stats.fp_count}</span>
			</span>
		</div>
		<span class="text-gray-700">|</span>
		<div class="flex items-center gap-1.5">
			<span class="text-gray-600 text-[10px] uppercase tracking-wider font-semibold">Model</span>
			<span class="font-semibold {stageColor}">{stats.model_stage}</span>
		</div>
		<span class="text-gray-700">|</span>
		<span class="text-gray-600 italic text-xs">retrains on every submit</span>
	</div>
{/if}
