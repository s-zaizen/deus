<script lang="ts">
	import type { Language } from '$lib/types';

	const LANGUAGES: { value: Language; label: string }[] = [
		{ value: 'auto', label: 'Auto-detect' },
		{ value: 'python', label: 'Python' },
		{ value: 'rust', label: 'Rust' },
		{ value: 'javascript', label: 'JavaScript' },
		{ value: 'typescript', label: 'TypeScript' },
		{ value: 'go', label: 'Go' },
		{ value: 'java', label: 'Java' },
		{ value: 'ruby', label: 'Ruby' },
		{ value: 'c', label: 'C' },
		{ value: 'cpp', label: 'C++' }
	];

	let {
		language,
		onlanguagechange,
		onscan,
		scanning,
		hasFindings,
		onsubmittoverify
	}: {
		language: Language;
		onlanguagechange: (lang: Language) => void;
		onscan: () => void;
		scanning: boolean;
		hasFindings: boolean;
		onsubmittoverify: () => void;
	} = $props();
</script>

<div class="flex items-center gap-2">
	<select
		value={language}
		onchange={(e) => onlanguagechange((e.currentTarget as HTMLSelectElement).value as Language)}
		class="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 rounded focus:outline-none focus:border-indigo-500 cursor-pointer"
	>
		{#each LANGUAGES as l}
			<option value={l.value}>{l.label}</option>
		{/each}
	</select>

	<button
		onclick={onscan}
		disabled={scanning}
		class={[
			'flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all',
			scanning
				? 'bg-green-800/80 text-green-300 cursor-not-allowed'
				: 'bg-green-600 hover:bg-green-500 hover:shadow-[0_0_12px_rgba(22,163,74,0.25)] text-white cursor-pointer'
		].join(' ')}
	>
		{#if scanning}
			<svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
			</svg>
			Scanning…
		{:else}
			<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
				<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
			</svg>
			Scan
		{/if}
	</button>

	<div class="w-px h-4 bg-gray-700/60"></div>

	<button
		onclick={onsubmittoverify}
		disabled={!hasFindings || scanning}
		class={[
			'flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold border transition-all',
			hasFindings && !scanning
				? 'border-indigo-500/60 text-indigo-300 hover:bg-indigo-900/30 hover:border-indigo-500 hover:shadow-[0_0_12px_rgba(99,102,241,0.15)] cursor-pointer'
				: 'border-gray-800 text-gray-700 cursor-not-allowed'
		].join(' ')}
	>
		<span>Send to Verify</span>
		<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
			<path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
		</svg>
	</button>
</div>
