<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteSet } from 'svelte/reactivity';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FileTree from '$lib/components/FileTree.svelte';
	import FindingCard from '$lib/components/FindingCard.svelte';
	import KnowledgeTab from '$lib/components/KnowledgeTab.svelte';
	import ModelTab from '$lib/components/ModelTab.svelte';
	import ScanPanel from '$lib/components/ScanPanel.svelte';
	import StatusBar from '$lib/components/StatusBar.svelte';
	import VerifyTab from '$lib/components/VerifyTab.svelte';
	import {
		scanCode,
		submitFeedback,
		getStats,
		getVerifyQueue,
		addToVerifyQueue,
		getKnowledgeHistory,
		submitToKnowledge
	} from '$lib/api';
	import { preloadHighlighter } from '$lib/highlighter';
	import { readFolder, flatFiles } from '$lib/folder';
	import { PLACEHOLDERS } from '$lib/placeholders';
	import { PUBLIC_MODE } from '$lib/flags';
	import type { Finding, Language, Label, Stats, VerifyCase, KnowledgeCase, FileNode } from '$lib/types';

	type Tab = 'scan' | 'verify' | 'knowledge' | 'model';

	// Verify is hidden in public deployments (model is frozen, so Submit
	// has no effect). Scan / Knowledge / Model stay visible — Model is
	// read-only metrics, useful for showcasing how the GBDT looks.
	const VISIBLE_TABS: readonly Tab[] = PUBLIC_MODE
		? (['scan', 'knowledge', 'model'] as const)
		: (['scan', 'verify', 'knowledge', 'model'] as const);

const TAB_DESCRIPTIONS: Record<Tab, string> = {
	scan: 'Scan code for vulnerabilities',
	verify: 'Review and label findings',
	knowledge: 'Browse verified cases',
	model: 'View model training status'
};

	// ── State ────────────────────────────────────────────────────────────────────

	let activeTab = $state<Tab>('scan');
	let language = $state<Language>('python');
	let code = $state(PLACEHOLDERS.python);
	let findings = $state<Finding[]>([]);
	let scanning = $state(false);
	let stats = $state<Stats | null>(null);
	let error = $state<string | null>(null);
	let focusedFindingId = $state<string | null>(null);

	let verifyCases = $state<VerifyCase[]>([]);
	let knowledgeHistory = $state<KnowledgeCase[]>([]);

	let folderRoot = $state<FileNode | null>(null);
	let selectedFile = $state<FileNode | null>(null);
	let scannedPaths = new SvelteSet<string>();
	let scanProgress = $state<{ current: number; total: number } | null>(null);

	const focusedFinding = $derived(findings.find((f) => f.id === focusedFindingId));
	const focusedLine = $derived(focusedFinding?.line_start ?? null);
	const currentFilename = $derived(selectedFile?.name);

	// ── Init ─────────────────────────────────────────────────────────────────────

	// Stats / queue / knowledge are fetched once at mount so the
	// StatusBar shows real numbers, then polled only while the user
	// sits on the Model tab — that's the only view where a ticking
	// label count matters. Other tabs stay frozen at the last fetch
	// (cheap and avoids hammering /api/stats every few seconds).
	const POLL_INTERVAL_MS = 30_000;
	const HEAVY_REFRESH_INTERVAL_MS = 60_000;
	let lastSeenTotalLabels = 0;
	let lastHeavyRefreshAt = 0;

	async function refreshHeavy() {
		try {
			verifyCases = await getVerifyQueue();
		} catch { /* backend not running */ }
		try {
			knowledgeHistory = await getKnowledgeHistory();
		} catch { /* backend not running */ }
		lastHeavyRefreshAt = Date.now();
	}

	async function pollTick() {
		try {
			const s = await getStats();
			stats = s;
			const moved = s.total_labels !== lastSeenTotalLabels;
			lastSeenTotalLabels = s.total_labels;
			if (moved && Date.now() - lastHeavyRefreshAt >= HEAVY_REFRESH_INTERVAL_MS) {
				await refreshHeavy();
			}
		} catch { /* backend not running */ }
	}

	onMount(() => {
		void preloadHighlighter();
		void refreshHeavy();
		void pollTick();
	});

	// Poll only while the Model tab is the active view. Switching away
	// tears down the interval; switching back re-runs an immediate fetch
	// and re-arms it. Other tabs see the last cached snapshot.
	$effect(() => {
		if (activeTab !== 'model') return;
		void pollTick();
		const tick = setInterval(() => void pollTick(), POLL_INTERVAL_MS);
		return () => clearInterval(tick);
	});

	// ── Helpers ──────────────────────────────────────────────────────────────────

	async function refreshStats() {
		try {
			stats = await getStats();
		} catch { /* backend not running */ }
	}

	// ── Handlers ─────────────────────────────────────────────────────────────────

	function handleLanguageChange(lang: Language) {
		language = lang;
		code = PLACEHOLDERS[lang];
		findings = [];
		focusedFindingId = null;
	}

	async function handleScan() {
		scanning = true;
		error = null;
		focusedFindingId = null;
		try {
			const result = await scanCode(code, language);
			findings = result.findings;
		} catch {
			error = 'Cannot connect to makina server. Run: docker compose up -d';
		} finally {
			scanning = false;
		}
	}

	async function handleSubmitToVerify() {
		if (findings.length === 0) return;
		try {
			const newCase = await addToVerifyQueue(null, code, language, findings);
			verifyCases = [...verifyCases, newCase];
		} catch {
			const localCase: VerifyCase = {
				caseNo: Date.now(),
				code,
				language,
				findings: [...findings],
				submittedAt: new Date().toISOString(),
				labels: {}
			};
			verifyCases = [...verifyCases, localCase];
		}
		findings = [];
		focusedFindingId = null;
		activeTab = 'verify';
	}

	function handleCaseLabel(caseNo: number, findingId: string, label: Label) {
		verifyCases = verifyCases.map((vc) =>
			vc.caseNo === caseNo
				? { ...vc, labels: { ...vc.labels, [findingId]: label } }
				: vc
		);
	}

	async function handleCaseSubmit(caseNo: number) {
		const vc = verifyCases.find((c) => c.caseNo === caseNo);
		if (!vc) return;

		await submitToKnowledge(caseNo, vc.labels);

		const knowledgeCase: KnowledgeCase = {
			caseNo: vc.caseNo,
			cveId: vc.cveId,
			code: vc.code,
			language: vc.language,
			findings: vc.findings,
			labels: { ...vc.labels },
			submittedAt: vc.submittedAt,
			verifiedAt: new Date().toISOString()
		};
		knowledgeHistory = [knowledgeCase, ...knowledgeHistory];
		verifyCases = verifyCases.filter((c) => c.caseNo !== caseNo);
		await refreshStats();
	}

	function handleFocusFinding(id: string) {
		focusedFindingId = id;
		activeTab = 'scan';
	}

	async function handleFolderDrop(item: DataTransferItem) {
		const root = await readFolder(item);
		if (!root) return;
		folderRoot = root;
		scannedPaths.clear();
		scanProgress = null;
		const files = flatFiles(root);
		if (files.length > 0) handleSelectFile(files[0]);
	}

	function handleSelectFile(node: FileNode) {
		if (!node.content || !node.language) return;
		selectedFile = node;
		code = node.content;
		language = node.language;
		findings = [];
		focusedFindingId = null;
	}

	async function handleScanAll() {
		if (!folderRoot) return;
		const files = flatFiles(folderRoot);
		scanProgress = { current: 0, total: files.length };
		for (let i = 0; i < files.length; i++) {
			const f = files[i];
			if (!f.content || !f.language) continue;
			try {
				const result = await scanCode(f.content, f.language);
				if (result.findings.length > 0) {
					await addToVerifyQueue(null, f.content, f.language, result.findings)
						.then((c) => (verifyCases = [...verifyCases, c]))
						.catch(() => {});
				}
				scannedPaths.add(f.path);
			} catch { /* continue */ }
			scanProgress = { current: i + 1, total: files.length };
		}
		scanProgress = null;
	}

	function handleClearFolder() {
		folderRoot = null;
		selectedFile = null;
		scannedPaths.clear();
		scanProgress = null;
	}
</script>

<div class="relative flex h-screen text-gray-100 overflow-hidden" style="background:#060a12;">

	<!-- Left rail: icon-only vertical tabs -->
	<aside class="relative z-10 flex w-16 shrink-0 flex-col bg-gray-950 border-r border-gray-800/80">
		<button
			onclick={() => (activeTab = 'scan')}
			aria-label="Home"
			class="flex items-center justify-center h-14 shrink-0 border-b border-gray-800/80 w-full hover:bg-gray-900 transition-colors"
		>
			<svg class="w-7 h-7 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
				<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
			</svg>
		</button>

		<nav class="flex flex-col gap-1 p-2">
			{#each VISIBLE_TABS as tab}
				<button
					onclick={() => (activeTab = tab)}
					class={[
						'group relative flex items-center justify-center h-11 rounded-xl transition-all',
						activeTab === tab
							? 'bg-indigo-600/20 text-indigo-300'
							: 'text-gray-600 hover:text-gray-400 hover:bg-gray-900'
					].join(' ')}
				>
					<!-- Active indicator -->
					{#if activeTab === tab}
						<span class="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 bg-indigo-500 rounded-r-full"></span>
					{/if}
					<!-- Tooltip -->
					<span class="absolute left-full ml-3 px-2.5 py-1.5 bg-gray-800 text-gray-200 text-xs rounded-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-gray-700/60 shadow-xl z-50">
						{TAB_DESCRIPTIONS[tab]}
					</span>
					<span class="relative">
						{#if tab === 'scan'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
							</svg>
						{:else if tab === 'verify'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
							</svg>
						{:else if tab === 'knowledge'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A9 9 0 006 18c2.305 0 4.408.867 6 2.292m0-14.25a8.967 8.967 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A9 9 0 0118 18a8.967 8.967 0 01-6-2.292m0-14.25v14.25" />
							</svg>
						{:else if tab === 'model'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
							</svg>
						{/if}
						{#if tab === 'verify' && verifyCases.length > 0}
							<span class="absolute -top-1 -right-1.5 w-4 h-4 text-[10px] font-bold bg-indigo-500 text-white rounded-full flex items-center justify-center">
								{verifyCases.length}
							</span>
						{/if}
					</span>
				</button>
			{/each}
		</nav>
	</aside>

	<!-- Main column -->
	<div class="relative z-10 flex flex-col flex-1 min-w-0 min-h-0 bg-gray-950">

	<!-- Content -->
	{#if activeTab === 'scan'}
		<div class="flex flex-1 min-h-0">
			<!-- File tree sidebar — always present; shows an empty-state
			     placeholder until a folder is loaded so users see the
			     workspace layout from the first paint. -->
			<div class="hidden lg:flex w-56 xl:w-64 shrink-0 flex-col bg-gray-950 border-r border-gray-800/80">
				{#if folderRoot}
					<FileTree
						root={folderRoot}
						selectedPath={selectedFile?.path ?? null}
						{scannedPaths}
						{scanProgress}
						onselect={handleSelectFile}
						onscanall={handleScanAll}
						onclear={handleClearFolder}
					/>
				{:else}
					<div class="flex h-full flex-col">
						<div class="flex items-center gap-2 h-11 px-3 border-b border-gray-800/80 shrink-0">
							<span class="text-[10px] font-bold text-gray-500 uppercase tracking-wider truncate flex-1">
								Explorer
							</span>
						</div>
						<div class="flex flex-1 flex-col items-center justify-center gap-4 px-4 text-center">
							<div class="w-14 h-14 rounded-xl bg-gray-900 flex items-center justify-center border border-dashed border-gray-700/60">
								<svg
									class="w-7 h-7 text-gray-500"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
									stroke-width="1.4"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
									/>
								</svg>
							</div>
							<div class="space-y-1">
								<p class="text-sm text-gray-300 font-medium">
									Drop a folder here
								</p>
								<p class="text-xs text-gray-500 leading-relaxed">
									or paste code into the editor
								</p>
							</div>
						</div>
					</div>
				{/if}
			</div>

			<!-- Editor -->
			<div class="flex flex-1 flex-col min-h-0 border-r border-gray-800/60">
				<CodeEditor
					value={code}
					onchange={(v) => (code = v)}
					{language}
					{findings}
					{focusedLine}
					onFolderDrop={folderRoot ? undefined : handleFolderDrop}
					filename={currentFilename}
				/>
			</div>

			<!-- Findings panel -->
			<div class="hidden lg:flex w-80 xl:w-96 shrink-0 flex-col bg-gray-950 border-l border-gray-800/80">
				<!-- Findings header with scan controls -->
				<div class="flex items-center gap-2 h-11 px-3 border-b border-gray-800/80 shrink-0">
					<select
						value={language}
						onchange={(e) => handleLanguageChange((e.currentTarget as HTMLSelectElement).value as Language)}
						class="text-[10px] font-semibold uppercase tracking-wider px-2 py-1 bg-gray-900 text-gray-400 border border-gray-700 rounded focus:outline-none focus:border-indigo-500 cursor-pointer"
					>
						<option value="auto">Auto</option>
						<option value="python">Python</option>
						<option value="rust">Rust</option>
						<option value="javascript">JS</option>
						<option value="typescript">TS</option>
						<option value="go">Go</option>
						<option value="java">Java</option>
						<option value="ruby">Ruby</option>
						<option value="c">C</option>
						<option value="cpp">C++</option>
					</select>
					<button
						onclick={handleScan}
						disabled={scanning}
						class="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-semibold transition-all {scanning ? 'bg-green-900/50 text-green-400 cursor-not-allowed' : 'bg-green-600 hover:bg-green-500 text-white'}"
					>
						{#if scanning}
							<svg class="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
							Scanning
						{:else}
							<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>
							Scan
						{/if}
					</button>
					<button
						onclick={handleSubmitToVerify}
						disabled={!findings.length || scanning}
						class="ml-auto flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-semibold border transition-all {findings.length && !scanning ? 'border-indigo-500/60 text-indigo-300 hover:bg-indigo-900/30' : 'border-gray-800 text-gray-700 cursor-not-allowed'}"
					>
						<span>Send</span>
						<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/></svg>
					</button>
				</div>
				<div class="flex-1 overflow-y-auto p-3 flex-col gap-2">
					{#if error}
						<div class="bg-red-900/40 border border-red-800 rounded-lg p-3 text-sm text-red-300 mb-2">
							{error}
						</div>
					{/if}
					{#if findings.length === 0 && !error}
						<div class="flex flex-col items-center justify-center gap-3 text-center py-10">
							<div class="w-12 h-12 rounded-xl bg-gray-900 flex items-center justify-center border border-dashed border-gray-700/60">
								<svg class="w-6 h-6 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
									<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
								</svg>
							</div>
							<div class="space-y-0.5">
								<p class="text-gray-300 text-sm font-medium">
									{scanning ? 'Scanning…' : 'No findings'}
								</p>
								<p class="text-gray-500 text-xs">
									{scanning ? 'Analyzing…' : 'Click Scan to analyze'}
								</p>
							</div>
						</div>
					{/if}
					{#each findings as f (f.id)}
						<FindingCard
							finding={f}
							{language}
							onlabel={async (id, label) => {
								await submitFeedback(id, label);
								await refreshStats();
							}}
							onfocus={() => handleFocusFinding(f.id)}
							focused={f.id === focusedFindingId}
						/>
					{/each}
				</div>
			</div>
		</div>
	{:else if activeTab === 'verify'}
		<VerifyTab
			cases={verifyCases}
			onlabel={handleCaseLabel}
			onsubmit={handleCaseSubmit}
		/>
	{:else if activeTab === 'knowledge'}
		<KnowledgeTab history={knowledgeHistory} />
	{:else if activeTab === 'model'}
		<ModelTab {stats} historyCount={knowledgeHistory.length} />
	{/if}

	<!-- Status bar -->
	<StatusBar {stats} />
	</div>
</div>
