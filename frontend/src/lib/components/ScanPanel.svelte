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
		actionEnabled,
		onaction,
		compact = false,
		actionLabel = 'Send to Audit',
		compactActionLabel = 'Audit'
	}: {
		language: Language;
		onlanguagechange: (lang: Language) => void;
		onscan: () => void;
		scanning: boolean;
		actionEnabled: boolean;
		onaction: () => void;
		compact?: boolean;
		actionLabel?: string;
		compactActionLabel?: string;
	} = $props();

	const scanLabel = $derived(scanning ? (compact ? 'Scanning' : 'Scanning...') : 'Scan');
	const sendLabel = $derived(compact ? compactActionLabel : actionLabel);
</script>

<div class={compact ? 'flex flex-nowrap items-center gap-1.5 overflow-hidden' : 'flex flex-wrap items-center gap-2'}>
	<select
		value={language}
		onchange={(e) => onlanguagechange((e.currentTarget as HTMLSelectElement).value as Language)}
		aria-label="Language"
		class={[
			'rounded border border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] py-1 text-xs font-medium text-[var(--mk-text-soft)] focus:border-[#8b5cf6] focus:outline-none cursor-pointer',
			compact ? 'w-[5.5rem] shrink-0 px-1.5' : 'min-w-[6rem] flex-1 sm:flex-none px-2.5'
		].join(' ')}
	>
		{#each LANGUAGES as l}
			<option value={l.value}>{l.label}</option>
		{/each}
	</select>

	<button
		onclick={onscan}
		disabled={scanning}
		class={[
			'flex items-center justify-center gap-1 rounded-lg text-xs font-semibold transition-all',
			compact ? 'shrink-0 px-2 py-1 min-w-[4rem]' : 'min-w-[5.5rem] px-3.5 py-1.5 gap-1.5',
			scanning
				? 'bg-teal-950/80 text-teal-300 cursor-not-allowed'
				: 'bg-teal-600 hover:bg-teal-500 text-white shadow-[0_0_18px_rgba(20,184,166,0.16)] cursor-pointer'
		].join(' ')}
	>
		{#if scanning}
			<svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
			</svg>
			{scanLabel}
		{:else}
			<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
				<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
			</svg>
			{scanLabel}
		{/if}
	</button>

	<div class={compact ? 'hidden' : 'hidden h-4 w-px bg-[var(--mk-border-strong)] sm:block'}></div>

	<button
		onclick={onaction}
		disabled={!actionEnabled || scanning}
		class={[
			'flex items-center justify-center gap-1 rounded-lg border text-xs font-semibold transition-all',
			compact ? 'shrink-0 px-2 py-1 min-w-[4.5rem]' : 'min-w-[7rem] px-3.5 py-1.5 gap-1.5',
			actionEnabled && !scanning
				? 'border-violet-500/70 text-violet-200 hover:bg-violet-950/35 hover:border-violet-400 shadow-[0_0_18px_rgba(79,70,229,0.10)] cursor-pointer'
				: 'border-[var(--mk-border)] text-gray-700 cursor-not-allowed'
		].join(' ')}
	>
		<span class="whitespace-nowrap">{sendLabel}</span>
		<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
			<path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
		</svg>
	</button>
</div>
