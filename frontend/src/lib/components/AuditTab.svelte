<script lang="ts">
	import { onMount, tick } from 'svelte';
	import {
		DEFAULT_ANTHROPIC_MODEL,
		DEFAULT_MAX_OUTPUT_TOKENS,
		DEFAULT_OPENAI_MODEL,
		runAuditWorkflow
	} from '$lib/audit';
	import type { AuditCase, AuditProvider, AuditStepResult, AuditStepStatus, Finding } from '$lib/types';
	import MarkdownReport from '$lib/components/MarkdownReport.svelte';
	import { PUBLIC_MODE } from '$lib/flags';
	import { severityTone } from '$lib/theme';

	let { auditCase }: { auditCase: AuditCase | null } = $props();

	const SETTINGS_KEY = 'makina.audit.settings.v1';
	const PROVIDERS: { value: AuditProvider; label: string }[] = [
		{ value: 'openai', label: 'OpenAI' },
		{ value: 'anthropic', label: 'Anthropic' }
	];

	interface StoredSettings {
		provider?: AuditProvider;
		models?: Partial<Record<AuditProvider, string>>;
		maxOutputTokens?: number;
		rememberKeys?: boolean;
		openaiKey?: string;
		anthropicKey?: string;
	}

	let mounted = false;
	let activeAuditCaseId = $state<string | null>(null);
	let provider = $state<AuditProvider>('openai');
	let models = $state<Record<AuditProvider, string>>({
		openai: DEFAULT_OPENAI_MODEL,
		anthropic: DEFAULT_ANTHROPIC_MODEL
	});
	let openaiKey = $state('');
	let anthropicKey = $state('');
	let rememberKeys = $state(false);
	let maxOutputTokens = $state(DEFAULT_MAX_OUTPUT_TOKENS);
	let results = $state<AuditStepResult[]>([]);
	let reportMarkdown = $state('');
	let stepsExpanded = $state(false);
	let running = $state(false);
	let runError = $state<string | null>(null);
	let selectedFindingId = $state<string | null>(null);
	let lastAuditFindingIds = $state<string[]>([]);

	const currentApiKey = $derived(PUBLIC_MODE ? '' : provider === 'openai' ? openaiKey : anthropicKey);
	const currentModel = $derived(models[provider]);
	const selectedFinding = $derived(
		auditCase?.findings.find((finding) => finding.id === selectedFindingId) ?? null
	);
	const currentRunFindings = $derived(auditCase ? (selectedFinding ? [selectedFinding] : auditCase.findings) : []);
	const canRunAll = $derived(
		!PUBLIC_MODE &&
		Boolean(auditCase && currentApiKey.trim() && currentModel.trim() && !running && auditCase.findings.length > 0)
	);
	const canRunSelected = $derived(
		!PUBLIC_MODE && Boolean(selectedFinding && currentApiKey.trim() && currentModel.trim() && !running)
	);
	const canRun = $derived(selectedFinding ? canRunSelected : canRunAll);
	const findingSummary = $derived(
		auditCase
			? `${auditCase.findings.length} finding${auditCase.findings.length === 1 ? '' : 's'}`
			: 'No scan'
	);

	interface ReportSection {
		id: string;
		title: string;
		source: string;
		findingId: string | null;
	}

	function reportIdForIndex(index: number) {
		return `MAKINA-${String(index + 1).padStart(3, '0')}`;
	}

	function splitReportMarkdown(markdown: string): Omit<ReportSection, 'findingId'>[] {
		const source = markdown.trim();
		if (!source) return [];

		const matches = [...source.matchAll(/^#\s+(MAKINA-\d{3})(?::\s*(.*?))?\s*$/gm)];
		if (matches.length === 0) {
			return [{ id: 'MAKINA-001', title: 'Audit Report', source }];
		}

		return matches.map((match, index) => {
			const start = match.index ?? 0;
			const headerEnd = start + match[0].length;
			const nextStart = matches[index + 1]?.index ?? source.length;
			return {
				id: match[1],
				title: match[2]?.trim() || 'Audit Report',
				source: source.slice(headerEnd, nextStart).trim()
			};
		});
	}

	const reportSections = $derived(
		splitReportMarkdown(reportMarkdown).map((section, index) => ({
			...section,
			findingId: lastAuditFindingIds[index] ?? auditCase?.findings[index]?.id ?? null
		}))
	);

	onMount(() => {
		if (PUBLIC_MODE) {
			openaiKey = '';
			anthropicKey = '';
			rememberKeys = false;
			mounted = true;
			return;
		}
		try {
			const raw = localStorage.getItem(SETTINGS_KEY);
			if (raw) {
				const stored = JSON.parse(raw) as StoredSettings;
				if (stored.provider === 'openai' || stored.provider === 'anthropic') provider = stored.provider;
				models = {
					openai: stored.models?.openai || DEFAULT_OPENAI_MODEL,
					anthropic: stored.models?.anthropic || DEFAULT_ANTHROPIC_MODEL
				};
				maxOutputTokens = Math.max(
					stored.maxOutputTokens || DEFAULT_MAX_OUTPUT_TOKENS,
					DEFAULT_MAX_OUTPUT_TOKENS
				);
				rememberKeys = stored.rememberKeys === true;
				if (rememberKeys) {
					openaiKey = stored.openaiKey || '';
					anthropicKey = stored.anthropicKey || '';
				}
			}
		} catch {
			// Ignore malformed local settings.
		}
		mounted = true;
	});

	$effect(() => {
		if (!mounted || PUBLIC_MODE) return;
		const stored: StoredSettings = {
			provider,
			models,
			maxOutputTokens,
			rememberKeys
		};
		if (rememberKeys) {
			stored.openaiKey = openaiKey;
			stored.anthropicKey = anthropicKey;
		}
		localStorage.setItem(SETTINGS_KEY, JSON.stringify(stored));
	});

	$effect(() => {
		const nextAuditCaseId = auditCase?.id ?? null;
		if (nextAuditCaseId === activeAuditCaseId) return;

		activeAuditCaseId = nextAuditCaseId;
		selectedFindingId = null;
		lastAuditFindingIds = [];
		results = [];
		reportMarkdown = '';
		stepsExpanded = false;
		runError = null;
	});

	async function runAudit(scope: 'current' | 'all' = 'current') {
		if (!auditCase) return;
		if (PUBLIC_MODE) {
			runError = 'LLM Audit is disabled in public demo mode.';
			return;
		}

		const findings = scope === 'all' ? auditCase.findings : currentRunFindings;
		if (findings.length === 0) return;
		if ((scope === 'all' && !canRunAll) || (scope === 'current' && !canRun)) return;

		if (scope === 'all') selectedFindingId = null;
		running = true;
		runError = null;
		results = [];
		reportMarkdown = '';
		stepsExpanded = false;
		lastAuditFindingIds = findings.map((finding) => finding.id);
		try {
			const response = await runAuditWorkflow({
				provider,
				apiKey: currentApiKey.trim(),
				model: currentModel.trim(),
				maxOutputTokens,
				auditCase,
				findings
			});
			results = response.results;
			reportMarkdown = response.reportMarkdown;
			await tick();
			if (scope === 'current' && selectedFindingId) scrollToFindingReport(selectedFindingId);
		} catch (err) {
			runError = err instanceof Error ? err.message : String(err);
		} finally {
			running = false;
		}
	}

	async function selectFinding(findingId: string) {
		selectedFindingId = findingId;
		await tick();
		scrollToFindingReport(findingId);
	}

	function clearFindingSelection() {
		selectedFindingId = null;
	}

	function formatDate(iso: string) {
		return new Date(iso).toLocaleString('ja-JP', {
			year: 'numeric',
			month: '2-digit',
			day: '2-digit',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	function setModel(value: string) {
		models = { ...models, [provider]: value };
	}

	function reportIndexForFinding(findingId: string) {
		return reportSections.findIndex((section) => section.findingId === findingId);
	}

	function findingForSection(section: ReportSection) {
		if (!section.findingId) return null;
		return auditCase?.findings.find((finding) => finding.id === section.findingId) ?? null;
	}

	function reportBadgeForFinding(finding: Finding, index: number) {
		const sectionIndex = reportIndexForFinding(finding.id);
		if (sectionIndex >= 0) return reportSections[sectionIndex].id;

		const pendingIndex = lastAuditFindingIds.indexOf(finding.id);
		if (pendingIndex >= 0) return reportIdForIndex(pendingIndex);
		if (reportMarkdown || results.length > 0 || running) return 'Not audited';
		return reportIdForIndex(index);
	}

	function domId(value: string) {
		return value.replace(/[^A-Za-z0-9_-]/g, '-');
	}

	function reportElementId(section: ReportSection, index: number) {
		return section.findingId ? `audit-report-${domId(section.findingId)}` : `audit-report-${index}`;
	}

	function scrollToFindingReport(findingId: string) {
		const sectionIndex = reportIndexForFinding(findingId);
		if (sectionIndex < 0) return;

		const section = reportSections[sectionIndex];
		document.getElementById(reportElementId(section, sectionIndex))?.scrollIntoView({
			behavior: 'smooth',
			block: 'start'
		});
	}

	function findingCardClass(finding: Finding) {
		const selected = selectedFindingId === finding.id;
		const audited = reportIndexForFinding(finding.id) >= 0;
		const tone = severityTone(finding.severity);
		return [
			'w-full rounded-lg border border-l-4 p-3 text-left transition-colors',
			selected
				? 'border-violet-500 border-l-[var(--mk-copper)] bg-violet-950/30 shadow-[0_0_0_1px_rgba(139,92,246,0.25)]'
				: audited
					? `border-teal-900/70 ${tone.border} bg-[var(--mk-bg-elevated)] hover:border-teal-800`
					: `border-[var(--mk-border)] ${tone.border} bg-[var(--mk-bg-elevated)] hover:border-[var(--mk-border-strong)]`,
			'cursor-pointer'
		].join(' ');
	}

	function reportCardClass(section: ReportSection, finding: Finding | null) {
		const selected = section.findingId !== null && section.findingId === selectedFindingId;
		const tone = severityTone(finding?.severity);
		return [
			'overflow-hidden rounded-lg border border-l-4 transition-colors',
			selected
				? `border-violet-500 border-l-[var(--mk-copper)] ${tone.panel} shadow-[0_0_0_1px_rgba(139,92,246,0.25),0_0_26px_rgba(79,70,229,0.12)]`
				: `border-[var(--mk-border)] ${tone.border} bg-[var(--mk-bg-elevated)]`
		].join(' ');
	}

	function statusClass(status: AuditStepStatus) {
		if (status === 'complete') return 'border-teal-800 bg-teal-950/60 text-teal-300';
		if (status === 'running') return 'border-violet-800 bg-violet-950/60 text-violet-300';
		if (status === 'error') return 'border-red-800 bg-red-950/60 text-red-300';
		return 'border-[var(--mk-border)] bg-[var(--mk-bg-panel)] text-gray-600';
	}
</script>

<div class="flex flex-1 min-h-0 flex-col bg-[var(--mk-bg)] lg:flex-row">
	<!-- Settings sidebar -->
	<aside class="flex max-h-[45vh] w-full shrink-0 flex-col border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)] lg:max-h-none lg:w-80 lg:border-b-0 lg:border-r">
		<!-- Header -->
		<div class="flex h-11 shrink-0 items-center justify-between border-b border-[var(--mk-border)] px-4">
			<div class="flex items-center gap-2 min-w-0">
				<h2 class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Audit</h2>
				<span class="rounded border border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] px-2 py-0.5 text-[10px] font-semibold text-[var(--mk-text-soft)]">
					{findingSummary}
				</span>
			</div>
		</div>

		<div class="flex-1 overflow-y-auto p-4 space-y-5">
			{#if PUBLIC_MODE}
				<section class="rounded-lg border border-amber-900/70 bg-amber-950/20 p-3">
					<p class="text-[10px] font-bold uppercase tracking-widest text-amber-300">Public demo mode</p>
					<p class="mt-2 text-xs leading-relaxed text-amber-100/80">
						LLM Audit is disabled on makina.sh because provider API keys would be forwarded to the hosted backend. Run Makina locally or in a private deployment to use OpenAI or Anthropic.
					</p>
				</section>
			{:else}
				<!-- Provider toggle -->
				<div class="grid grid-cols-2 gap-1 rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-1">
					{#each PROVIDERS as item}
						<button
							onclick={() => (provider = item.value)}
							class={[
								'relative z-0 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors',
								provider === item.value
									? 'bg-violet-600 text-white shadow-[0_0_18px_rgba(139,92,246,0.18)]'
									: 'text-gray-500 hover:bg-[var(--mk-bg-hover)] hover:text-[var(--mk-text-soft)] cursor-pointer'
							].join(' ')}
						>
							{item.label}
						</button>
					{/each}
				</div>

				<section class="space-y-3">
					<label class="block space-y-1">
						<span class="text-[10px] font-bold uppercase tracking-wider text-gray-600">API Key</span>
						<input
							type="password"
							value={currentApiKey}
							oninput={(e) => {
								if (provider === 'openai') openaiKey = e.currentTarget.value;
								else anthropicKey = e.currentTarget.value;
							}}
							placeholder={provider === 'openai' ? 'sk-...' : 'sk-ant-...'}
							class="w-full rounded-md border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-3 py-2 text-xs text-[var(--mk-text)] placeholder-gray-700 focus:border-violet-500/80 focus:outline-none"
						/>
					</label>

					<label class="flex items-center gap-2 text-xs text-gray-500">
						<input
							type="checkbox"
							bind:checked={rememberKeys}
							class="h-3.5 w-3.5 rounded border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] accent-violet-600"
						/>
						<span>Remember key in this browser</span>
					</label>

					<label class="block space-y-1">
						<span class="text-[10px] font-bold uppercase tracking-wider text-gray-600">Model</span>
						<input
							type="text"
							value={currentModel}
							oninput={(e) => setModel(e.currentTarget.value)}
							class="w-full rounded-md border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-3 py-2 font-mono text-xs text-[var(--mk-text)] focus:border-violet-500/80 focus:outline-none"
						/>
					</label>

					<label class="block space-y-1">
						<span class="text-[10px] font-bold uppercase tracking-wider text-gray-600">Max Output Tokens</span>
						<input
							type="number"
							min="256"
							max="8000"
							bind:value={maxOutputTokens}
							class="w-full rounded-md border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-3 py-2 font-mono text-xs text-[var(--mk-text)] focus:border-violet-500/80 focus:outline-none"
						/>
					</label>
				</section>
			{/if}
		</div>
	</aside>

	<!-- Main area -->
	<main class="flex flex-1 min-w-0 flex-col min-h-0">
		<!-- Header -->
		<div class="flex h-11 shrink-0 items-center justify-between border-b border-[var(--mk-border)] px-4">
			<div class="flex items-center gap-3 min-w-0 overflow-hidden">
				<h1 class="text-sm font-semibold text-[var(--mk-text)] shrink-0">LLM Audit</h1>
				{#if auditCase}
					<div class="hidden sm:flex items-center gap-2 text-xs text-gray-500 min-w-0">
						<span class="font-mono shrink-0">{auditCase.language}</span>
						<span class="shrink-0 text-gray-700">·</span>
						<span class="shrink-0">{auditCase.findings.length} findings</span>
						<span class="shrink-0 text-gray-700">·</span>
						<span class="shrink-0">{formatDate(auditCase.createdAt)}</span>
						{#if auditCase.scanId}
							<span class="shrink-0 text-gray-700">·</span>
							<span class="font-mono text-gray-600 truncate">{auditCase.scanId}</span>
						{/if}
					</div>
				{:else}
					<p class="text-xs text-gray-600 truncate">Send findings from Scan to start an audit.</p>
				{/if}
			</div>

			<div class="flex items-center gap-2 shrink-0">
				{#if selectedFinding}
					<button
						onclick={() => runAudit('all')}
						disabled={!canRunAll}
						class={[
							'inline-flex items-center justify-center rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors',
							canRunAll
								? 'border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] text-[var(--mk-text-soft)] hover:border-violet-500/60 hover:bg-[var(--mk-bg-hover)] cursor-pointer'
								: 'border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] text-gray-700 cursor-not-allowed'
						].join(' ')}
					>
						Run All
					</button>
				{/if}

				<button
					onclick={() => runAudit()}
					disabled={!canRun}
					class={[
						'inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors',
						canRun
							? 'bg-violet-600 text-white hover:bg-violet-500 shadow-[0_0_18px_rgba(139,92,246,0.18)] cursor-pointer'
							: 'bg-[var(--mk-bg-elevated)] text-gray-700 border border-[var(--mk-border)] cursor-not-allowed'
					].join(' ')}
				>
					{#if running}
						<svg class="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
							<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
							<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
						</svg>
						Running
					{:else if selectedFinding}
						Run Selected
					{:else}
						Run Audit
					{/if}
				</button>
			</div>
		</div>

		{#if PUBLIC_MODE}
			<div class="border-b border-amber-900/50 bg-amber-950/10 px-4 py-3 text-xs leading-relaxed text-amber-100/80">
				<span class="font-semibold text-amber-300">Public demo:</span>
				Hosted LLM Audit is unavailable because API keys must not be sent to this deployment.
			</div>
		{/if}

		{#if !auditCase}
			<div class="flex flex-1 items-center justify-center px-6 text-center">
				<div class="max-w-sm">
					<div class="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl border border-dashed border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)]">
						<svg class="h-6 w-6 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
							<path stroke-linecap="round" stroke-linejoin="round" d="M9 6.75h6M9 12h6m-6 5.25h3.5M5.25 3.75h13.5A1.5 1.5 0 0120.25 5.25v13.5a1.5 1.5 0 01-1.5 1.5H5.25a1.5 1.5 0 01-1.5-1.5V5.25a1.5 1.5 0 011.5-1.5z" />
						</svg>
					</div>
					<p class="text-sm font-medium text-gray-400">No audit input</p>
					<p class="mt-1 text-xs leading-relaxed text-gray-600">
						Run a scan, then send the findings to Audit.
					</p>
				</div>
			</div>
		{:else}
			<div class="flex flex-1 min-h-0 flex-col xl:flex-row">
				<!-- Scanner Findings list -->
				<section class="flex shrink-0 flex-col border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)] xl:h-auto xl:w-80 xl:border-b-0 xl:border-r">
					<div class="flex h-10 shrink-0 items-center justify-between gap-3 border-b border-[var(--mk-border)] px-4">
						<h3 class="text-[10px] font-bold uppercase tracking-widest text-gray-600">Scanner Findings</h3>
						<div class="flex items-center gap-2">
							{#if selectedFinding}
								<button
									onclick={clearFindingSelection}
									class="text-[10px] font-semibold text-gray-500 hover:text-gray-300 transition-colors cursor-pointer"
								>
									Clear
								</button>
							{/if}
							<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-0.5 text-[10px] font-semibold text-gray-500">
								{auditCase.findings.length}
							</span>
						</div>
					</div>
					<div class="flex-1 overflow-y-auto p-4 space-y-3">
						{#each auditCase.findings as finding, i (finding.id)}
							<button
								onclick={() => selectFinding(finding.id)}
								class={findingCardClass(finding)}
							>
								<div class="mb-2 flex flex-wrap items-center gap-2">
									<span class={['rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase shrink-0', severityTone(finding.severity).badge].join(' ')}>
										{finding.severity}
									</span>
									<span class="font-mono text-[10px] text-gray-500 shrink-0">{finding.rule_id}</span>
									{#if finding.cwe}
										<span class="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-500 shrink-0">
											{finding.cwe}
										</span>
									{/if}
									<span class="rounded bg-violet-950/40 border border-violet-900/50 px-1.5 py-0.5 font-mono text-[10px] text-violet-200 shrink-0">
										{reportBadgeForFinding(finding, i)}
									</span>
									<span class="ml-auto font-mono text-[10px] text-gray-600 shrink-0">
										L{finding.line_start}
									</span>
								</div>
								<p class="text-xs leading-snug text-gray-300 text-left">{finding.message}</p>
							</button>
						{/each}
					</div>
				</section>

				<!-- Report area -->
				<section class="flex-1 overflow-y-auto p-4">
					{#if runError}
						<div class="mb-4 rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">
							{runError}
						</div>
					{/if}

					{#if running && !reportMarkdown}
						<div class="rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]">
							<div class="flex items-center gap-2 border-b border-[var(--mk-border)] px-4 py-3">
								<h3 class="text-sm font-semibold text-gray-300">Audit Workflow</h3>
								<span class={['ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold uppercase', statusClass('running')].join(' ')}>
									running
								</span>
							</div>
							<div class="p-4">
								<p class="text-xs text-gray-500">Waiting for provider response...</p>
							</div>
						</div>
					{:else if reportMarkdown}
						<div class="mb-6 space-y-4">
							<div class="flex items-center justify-between gap-3">
								<h3 class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Security Report</h3>
								{#if results.length > 0}
									<button
										onclick={() => (stepsExpanded = !stepsExpanded)}
										class="text-[10px] font-semibold text-violet-300 hover:text-violet-200 transition-colors cursor-pointer"
									>
										{stepsExpanded ? 'Hide workflow steps' : 'Show workflow steps'}
									</button>
								{/if}
							</div>

							{#if reportSections.length > 0}
								<div class="space-y-4">
									{#each reportSections as section, i (`${section.id}-${section.findingId ?? i}`)}
										{@const sectionFinding = findingForSection(section)}
										{@const sectionTone = severityTone(sectionFinding?.severity)}
										<div
											id={reportElementId(section, i)}
											class={reportCardClass(section, sectionFinding)}
										>
											<div class={['h-1', sectionFinding ? sectionTone.track : 'bg-gray-700'].join(' ')}></div>
											<div class="border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)] px-4 py-3">
												<div class="flex items-center gap-2 min-w-0">
													<span class="font-mono text-xs font-bold text-violet-200 shrink-0">{section.id}</span>
													<span class="min-w-0 text-sm font-semibold text-gray-100 truncate">{section.title}</span>
													{#if section.findingId}
														<button
															onclick={() => section.findingId && selectFinding(section.findingId)}
															class="ml-auto text-[10px] font-semibold text-gray-500 hover:text-gray-300 transition-colors cursor-pointer shrink-0"
														>
															Focus finding
														</button>
													{/if}
												</div>
												{#if sectionFinding}
													<div class="mt-2 flex flex-wrap items-center gap-2">
														<span class={['rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase shrink-0', sectionTone.badge].join(' ')}>
															Impact {sectionFinding.severity}
														</span>
														<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-gray-400 shrink-0">
															{sectionFinding.rule_id}
														</span>
														{#if sectionFinding.cwe}
															<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-gray-400 shrink-0">
																{sectionFinding.cwe}
															</span>
														{/if}
														<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-gray-500 shrink-0">
															L{sectionFinding.line_start}
														</span>
													</div>
												{/if}
											</div>
											<div class="p-4">
												{#if section.source}
													<MarkdownReport source={section.source} />
												{:else}
													<p class="text-xs text-gray-700">No output.</p>
												{/if}
											</div>
										</div>
									{/each}
								</div>
							{:else}
								<div class="rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] p-4">
									<MarkdownReport source={reportMarkdown} />
								</div>
							{/if}
						</div>

						{#if stepsExpanded && results.length > 0}
							<div class="space-y-3">
								<h3 class="text-[10px] font-bold uppercase tracking-widest text-gray-500">Workflow Steps</h3>
								{#each results as result, i (result.id)}
									<div class="rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]">
										<div class="flex items-center gap-2 border-b border-[var(--mk-border)] px-4 py-3">
											<span class="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
												{i + 1}
											</span>
											<h3 class="text-sm font-semibold text-gray-300">{result.title}</h3>
											<span class={['ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold uppercase', statusClass(result.status)].join(' ')}>
												{result.status}
											</span>
										</div>
										<div class="p-4">
											{#if result.error}
												<p class="whitespace-pre-wrap text-xs leading-relaxed text-red-300">{result.error}</p>
											{:else if result.output}
												<MarkdownReport source={result.output} compact />
											{:else}
												<p class="text-xs text-gray-700">No output.</p>
											{/if}
											{#if result.durationMs !== null}
												<p class="mt-3 font-mono text-[10px] text-gray-600">{Math.round(result.durationMs / 100) / 10}s</p>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						{/if}
					{:else if results.length > 0}
						<div class="space-y-3">
							{#each results as result, i (result.id)}
								<div class="rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]">
									<div class="flex items-center gap-2 border-b border-[var(--mk-border)] px-4 py-3">
										<span class="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
											{i + 1}
										</span>
										<h3 class="text-sm font-semibold text-gray-300">{result.title}</h3>
										<span class={['ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold uppercase', statusClass(result.status)].join(' ')}>
											{result.status}
										</span>
									</div>
									<div class="p-4">
										{#if result.error}
											<p class="whitespace-pre-wrap text-xs leading-relaxed text-red-300">{result.error}</p>
										{:else if result.output}
											<MarkdownReport source={result.output} compact />
										{:else}
											<p class="text-xs text-gray-700">No output.</p>
										{/if}
										{#if result.durationMs !== null}
											<p class="mt-3 font-mono text-[10px] text-gray-600">{Math.round(result.durationMs / 100) / 10}s</p>
										{/if}
									</div>
								</div>
							{/each}
						</div>
					{:else}
						<div class="rounded-lg border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]">
							<div class="flex items-center gap-2 border-b border-[var(--mk-border)] px-4 py-3">
								<h3 class="text-sm font-semibold text-gray-300">Audit Workflow</h3>
								<span class={['ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold uppercase', statusClass('idle')].join(' ')}>
									idle
								</span>
							</div>
							<div class="p-4">
								<p class="text-xs text-gray-700">Not run.</p>
							</div>
						</div>
					{/if}
				</section>
			</div>
		{/if}
	</main>
</div>
