<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap, SvelteSet } from 'svelte/reactivity';
	import AuditTab from '$lib/components/AuditTab.svelte';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import FindingsList from '$lib/components/FindingsList.svelte';
	import FileTree from '$lib/components/FileTree.svelte';
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
		closeVerifyCase,
		getKnowledgeHistory,
		submitToKnowledge
	} from '$lib/api';
	import { preloadHighlighter } from '$lib/highlighter';
	import { readFolder, flatFiles } from '$lib/folder';
	import { PLACEHOLDERS } from '$lib/placeholders';
	import { PUBLIC_MODE } from '$lib/flags';
	import type { AuditCase, Finding, Language, Label, Stats, VerifyCase, KnowledgeCase, FileNode } from '$lib/types';

	type Tab = 'scan' | 'audit' | 'verify' | 'knowledge' | 'model';

	const VISIBLE_TABS: readonly Tab[] = ['scan', 'audit', 'verify', 'knowledge', 'model'] as const;

	const TAB_DESCRIPTIONS: Record<Tab, string> = {
		scan: 'Scan code for vulnerabilities',
		audit: 'Run LLM audit workflow',
		verify: 'Review and label findings',
		knowledge: 'Browse verified cases',
		model: 'View model training status'
	};
	const GITHUB_REPO_URL = 'https://github.com/s-zaizen/makina';

	// ── State ────────────────────────────────────────────────────────────────────

	let activeTab = $state<Tab>('scan');
	let language = $state<Language>('python');
	let code = $state(PLACEHOLDERS.python);
	let findings = $state<Finding[]>([]);
	let scanning = $state(false);
	let scanCompleted = $state(false);
	let resultsStale = $state(false);
	let currentScanId = $state<string | null>(null);
	let stats = $state<Stats | null>(null);
	let error = $state<string | null>(null);
	let focusedFindingId = $state<string | null>(null);

	let auditCase = $state<AuditCase | null>(null);
	let verifyCases = $state<VerifyCase[]>([]);
	let knowledgeHistory = $state<KnowledgeCase[]>([]);

	let folderRoot = $state<FileNode | null>(null);
	let selectedFile = $state<FileNode | null>(null);
	let scannedPaths = new SvelteSet<string>();
	let scannedFindingsByPath = new SvelteMap<string, Finding[]>();
	let scanIdsByPath = new SvelteMap<string, string>();
	let scanProgress = $state<{ current: number; total: number } | null>(null);
	let explorerDragging = $state(false);

	const focusedFinding = $derived(findings.find((f) => f.id === focusedFindingId));
	const focusedLine = $derived(focusedFinding?.line_start ?? null);
	const currentFilename = $derived(selectedFile?.name);
	const findingCountText = $derived(`${findings.length} finding${findings.length === 1 ? '' : 's'}`);
	const auditAllFindingCount = $derived(
		folderRoot
			? flatFiles(folderRoot).reduce(
					(total, file) => total + (scannedFindingsByPath.get(file.path)?.length ?? 0),
					0
				)
			: 0
	);

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
		scanCompleted = false;
		resultsStale = false;
		currentScanId = null;
		error = null;
	}

	function handleCodeChange(value: string) {
		if (value === code) return;
		const hasCurrentFindings = findings.length > 0;
		code = value;
		focusedFindingId = null;
		resultsStale = hasCurrentFindings;
		if (!hasCurrentFindings) scanCompleted = false;
		currentScanId = hasCurrentFindings ? currentScanId : null;
		error = null;
	}

	async function handleScan() {
		scanning = true;
		scanCompleted = false;
		resultsStale = false;
		error = null;
		findings = [];
		focusedFindingId = null;
		currentScanId = null;
		try {
			const result = await scanCode(code, language);
			findings = result.findings;
			currentScanId = result.scan_id;
			scanCompleted = true;
			if (selectedFile?.path) {
				scannedFindingsByPath.set(selectedFile.path, result.findings);
				scanIdsByPath.set(selectedFile.path, result.scan_id);
				scannedPaths.add(selectedFile.path);
			}
		} catch {
			error = 'Cannot connect to makina server. Run: docker compose up -d';
		} finally {
			scanning = false;
		}
	}

	function handleSendToAudit() {
		if (findings.length === 0 || resultsStale) return;
		auditCase = {
			id: crypto.randomUUID(),
			scanId: currentScanId,
			code,
			language,
			findings: [...findings],
			createdAt: new Date().toISOString()
		};
		activeTab = 'audit';
	}

	function scannedFilesWithFindings() {
		if (!folderRoot) return [];
		return flatFiles(folderRoot).filter((file) => (scannedFindingsByPath.get(file.path)?.length ?? 0) > 0);
	}

	function auditLanguageForFiles(files: FileNode[]): Language {
		const languages = new Set<Language>();
		for (const file of files) {
			if (file.language) languages.add(file.language);
		}
		return languages.size === 1 ? [...languages][0] : 'auto';
	}

	function buildAuditAllCode(files: FileNode[]) {
		return files
			.map((file) => {
				const languageHint = file.language ? ` | language: ${file.language}` : '';
				return [`/* File: ${file.path}${languageHint} */`, file.content ?? ''].join('\n');
			})
			.join('\n\n');
	}

	function handleSendAllToAudit() {
		const files = scannedFilesWithFindings();
		if (files.length === 0) return;

		const auditFindings = files.flatMap((file) =>
			(scannedFindingsByPath.get(file.path) ?? []).map((finding) => ({
				...finding,
				message: `[${file.path}] ${finding.message}`,
				source: `${finding.source} @ ${file.path}`,
				code_snippet: `// File: ${file.path}\n${finding.code_snippet}`
			}))
		);
		if (auditFindings.length === 0) return;

		const auditId = crypto.randomUUID();
		auditCase = {
			id: auditId,
			scanId: files.length === 1 ? (scanIdsByPath.get(files[0].path) ?? null) : `audit-all-${auditId}`,
			code: buildAuditAllCode(files),
			language: auditLanguageForFiles(files),
			findings: auditFindings,
			createdAt: new Date().toISOString()
		};
		activeTab = 'audit';
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

	async function handleCaseClose(caseNo: number) {
		const vc = verifyCases.find((c) => c.caseNo === caseNo);
		if (!vc) return;

		await closeVerifyCase(caseNo);

		const knowledgeCase: KnowledgeCase = {
			caseNo: vc.caseNo,
			cveId: vc.cveId,
			code: vc.code,
			language: vc.language,
			findings: vc.findings,
			labels: {},
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
		scannedFindingsByPath.clear();
		scanIdsByPath.clear();
		scanProgress = null;
		const files = flatFiles(root);
		if (files.length > 0) handleSelectFile(files[0]);
	}

	function dropItem(e: DragEvent): DataTransferItem | null {
		return Array.from(e.dataTransfer?.items ?? []).find((item) => item.kind === 'file') ?? null;
	}

	function handleExplorerDragEnter(e: DragEvent) {
		if (!dropItem(e)) return;
		e.preventDefault();
		if (!explorerDragging) explorerDragging = true;
	}

	function handleExplorerDragOver(e: DragEvent) {
		if (!dropItem(e)) return;
		e.preventDefault();
		if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
		if (!explorerDragging) explorerDragging = true;
	}

	function handleExplorerDragLeave(e: DragEvent) {
		const current = e.currentTarget as HTMLElement;
		const related = e.relatedTarget as Node | null;
		if (related && current.contains(related)) return;

		explorerDragging = false;
	}

	async function handleExplorerDrop(e: DragEvent) {
		const item = dropItem(e);
		if (!item) return;
		e.preventDefault();
		explorerDragging = false;
		await handleFolderDrop(item);
	}

	function handleSelectFile(node: FileNode) {
		if (!node.content) return;
		selectedFile = node;
		code = node.content;
		language = node.language ?? 'auto';
		findings = scannedFindingsByPath.get(node.path) ?? [];
		focusedFindingId = null;
		scanCompleted = scannedPaths.has(node.path);
		resultsStale = false;
		currentScanId = scanIdsByPath.get(node.path) ?? null;
		error = null;
	}

	async function handleScanAll() {
		if (!folderRoot) return;
		const files = flatFiles(folderRoot).filter((file) => Boolean(file.content));
		error = null;
		scanning = true;
		scanCompleted = false;
		resultsStale = false;
		focusedFindingId = null;
		currentScanId = null;
		scannedPaths.clear();
		scannedFindingsByPath.clear();
		scanIdsByPath.clear();
		if (selectedFile) findings = [];
		scanProgress = { current: 0, total: files.length };
		try {
			for (let i = 0; i < files.length; i++) {
				const f = files[i];
				if (!f.content) continue;
				const fileLanguage = f.language ?? 'auto';
				try {
					const result = await scanCode(f.content, fileLanguage);
					scannedFindingsByPath.set(f.path, result.findings);
					scanIdsByPath.set(f.path, result.scan_id);
					scannedPaths.add(f.path);
					if (selectedFile?.path === f.path) {
						findings = result.findings;
						currentScanId = result.scan_id;
						scanCompleted = true;
					}
				} catch { /* continue */ }
				scanProgress = { current: i + 1, total: files.length };
			}
			if (selectedFile && scannedPaths.has(selectedFile.path)) {
				scanCompleted = true;
			}
		} finally {
			scanning = false;
			scanProgress = null;
		}
	}

	function handleClearFolder() {
		folderRoot = null;
		selectedFile = null;
		scannedPaths.clear();
		scannedFindingsByPath.clear();
		scanIdsByPath.clear();
		scanProgress = null;
	}

	async function handleFindingLabel(id: string, label: Label) {
		await submitFeedback(id, label);
		await refreshStats();
	}

	function handleFindingClose(id: string) {
		findings = findings.filter((finding) => finding.id !== id);
		if (selectedFile?.path) {
			scannedFindingsByPath.set(selectedFile.path, findings);
		}
		if (focusedFindingId === id) focusedFindingId = null;
	}
</script>

<div class="mk-app-bg relative flex h-screen overflow-hidden text-[var(--mk-text)]">

	<!-- Left rail: icon-only vertical tabs -->
	<aside class="mk-rail relative z-10 flex h-full w-16 shrink-0 flex-col border-r">
		<nav class="no-scrollbar flex min-h-0 flex-1 flex-col gap-1 overflow-x-hidden overflow-y-auto p-2">
			{#each VISIBLE_TABS as tab}
				<button
					onclick={() => (activeTab = tab)}
					aria-label={TAB_DESCRIPTIONS[tab]}
					title={TAB_DESCRIPTIONS[tab]}
					class={[
						'group relative flex items-center justify-center h-11 rounded-xl transition-all',
						activeTab === tab
							? 'bg-violet-500/20 text-[var(--mk-text)] shadow-[inset_0_0_0_1px_rgba(139,92,246,0.24)]'
							: 'text-gray-600 hover:text-[var(--mk-text-soft)] hover:bg-[var(--mk-bg-elevated)]'
					].join(' ')}
				>
					<!-- Active indicator -->
					{#if activeTab === tab}
						<span class="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-r-full bg-[var(--mk-copper)] shadow-[0_0_14px_rgba(185,130,82,0.4)]"></span>
					{/if}
					<!-- Tooltip -->
					<span class="absolute left-full ml-3 px-2.5 py-1.5 bg-[var(--mk-bg-elevated)] text-[var(--mk-text)] text-xs rounded-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none border border-[var(--mk-border-strong)] shadow-xl z-50">
						{TAB_DESCRIPTIONS[tab]}
					</span>
					<span class="relative">
						{#if tab === 'scan'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
							</svg>
						{:else if tab === 'audit'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
								<path stroke-linecap="round" stroke-linejoin="round" d="M9 6.75h6M9 12h6m-6 5.25h3.5M5.25 3.75h13.5A1.5 1.5 0 0120.25 5.25v13.5a1.5 1.5 0 01-1.5 1.5H5.25a1.5 1.5 0 01-1.5-1.5V5.25a1.5 1.5 0 011.5-1.5z" />
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
						{#if tab === 'verify' && verifyCases.length > 0 && !PUBLIC_MODE}
							<span class="absolute -top-1 -right-1.5 w-4 h-4 text-[10px] font-bold bg-violet-500 text-white rounded-full flex items-center justify-center">
								{verifyCases.length}
							</span>
						{/if}
					</span>
				</button>
			{/each}
		</nav>
		<div class="flex h-9 shrink-0 items-center justify-center border-t border-[var(--mk-border)] bg-[var(--mk-bg-panel)] px-2">
			<a
				href={GITHUB_REPO_URL}
				target="_blank"
				rel="noreferrer"
				aria-label="Open GitHub repository"
				title="GitHub repository"
				class="group relative flex h-7 w-full items-center justify-center rounded-lg text-gray-600 transition-all hover:bg-[var(--mk-bg-elevated)] hover:text-[var(--mk-text-soft)]"
			>
				<span class="absolute left-full ml-3 rounded-lg border border-[var(--mk-border-strong)] bg-[var(--mk-bg-elevated)] px-2.5 py-1.5 text-xs text-[var(--mk-text)] opacity-0 shadow-xl transition-opacity pointer-events-none whitespace-nowrap group-hover:opacity-100 z-50">
					GitHub repository
				</span>
				<svg class="h-5 w-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
					<path
						fill-rule="evenodd"
						clip-rule="evenodd"
						d="M12 2C6.477 2 2 6.484 2 12.021c0 4.428 2.865 8.184 6.839 9.504.5.092.682-.217.682-.483 0-.238-.009-.868-.014-1.703-2.782.605-3.369-1.344-3.369-1.344-.455-1.158-1.11-1.466-1.11-1.466-.908-.621.069-.608.069-.608 1.004.071 1.532 1.032 1.532 1.032.892 1.531 2.341 1.089 2.91.833.091-.647.349-1.089.635-1.34-2.221-.253-4.555-1.113-4.555-4.951 0-1.094.39-1.988 1.03-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.563 9.563 0 0 1 12 6.844a9.55 9.55 0 0 1 2.504.337c1.909-1.296 2.748-1.026 2.748-1.026.546 1.378.203 2.397.1 2.65.64.7 1.028 1.594 1.028 2.688 0 3.847-2.338 4.695-4.566 4.943.359.31.678.923.678 1.86 0 1.343-.012 2.426-.012 2.756 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.021C22 6.484 17.523 2 12 2Z"
					/>
				</svg>
			</a>
		</div>
	</aside>

	<!-- Main column -->
	<div class="relative z-10 flex flex-col flex-1 min-w-0 min-h-0 bg-[var(--mk-bg)]">

	<!-- Content -->
		<div
			class="flex flex-1 min-h-0 flex-col lg:flex-row"
			style:display={activeTab === 'scan' ? 'flex' : 'none'}
			aria-hidden={activeTab !== 'scan'}
		>
			<div class="lg:hidden flex h-11 shrink-0 items-center overflow-hidden border-b border-[var(--mk-border)] bg-[var(--mk-bg-panel)] px-3">
				<ScanPanel
					{language}
					onlanguagechange={handleLanguageChange}
					onscan={handleScan}
					{scanning}
					actionEnabled={findings.length > 0 && !resultsStale}
					onaction={handleSendToAudit}
				/>
			</div>

			<!-- File tree sidebar — always present; shows an empty-state
			     placeholder until a folder is loaded so users see the
			     workspace layout from the first paint. -->
			<div
				class="relative hidden w-56 shrink-0 flex-col border-r border-[var(--mk-border)] bg-[var(--mk-bg-panel)] lg:flex xl:w-64"
				ondragenter={handleExplorerDragEnter}
				ondragover={handleExplorerDragOver}
				ondragleave={handleExplorerDragLeave}
				ondrop={handleExplorerDrop}
				role="region"
				aria-label="File explorer drop zone"
			>
				{#if explorerDragging}
					<div
						class="pointer-events-none absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 bg-[var(--mk-bg-panel)] px-4 text-center"
						style="border:2px dashed var(--mk-brand);"
					>
						<div class="flex h-12 w-12 items-center justify-center rounded-xl border border-violet-500/40 bg-violet-950/40">
							<svg
								class="h-6 w-6 text-violet-200"
								fill="none"
								viewBox="0 0 24 24"
								stroke="currentColor"
								stroke-width="1.5"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"
								/>
							</svg>
						</div>
						<div class="space-y-1">
							<p class="text-sm font-semibold text-violet-100">
								Drop to {folderRoot ? 'replace workspace' : 'open workspace'}
							</p>
							<p class="text-xs text-gray-500">
								Folders and supported source files are accepted.
							</p>
						</div>
					</div>
				{/if}
				{#if folderRoot}
					<FileTree
						root={folderRoot}
						selectedPath={selectedFile?.path ?? null}
						{scannedPaths}
						{scanProgress}
						onselect={handleSelectFile}
						onscanall={handleScanAll}
						onauditall={handleSendAllToAudit}
						auditAllEnabled={auditAllFindingCount > 0 && !scanning}
						auditAllCount={auditAllFindingCount}
						onclear={handleClearFolder}
					/>
				{:else}
					<div class="flex h-full flex-col">
						<div class="flex items-center gap-2 h-11 px-3 border-b border-[var(--mk-border)] shrink-0">
							<span class="text-[10px] font-bold text-gray-500 uppercase tracking-wider truncate flex-1">
								Explorer
							</span>
						</div>
						<div class="flex flex-1 flex-col items-center justify-center gap-4 px-4 text-center">
							<div class="w-14 h-14 rounded-xl bg-[var(--mk-bg-elevated)] flex items-center justify-center border border-dashed border-[var(--mk-border-strong)]">
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
			<div class="flex flex-1 flex-col min-h-0 border-r border-[var(--mk-border)]">
				<CodeEditor
					value={code}
					onchange={handleCodeChange}
					{language}
					{findings}
					{focusedLine}
					onFolderDrop={folderRoot ? undefined : handleFolderDrop}
					filename={currentFilename}
				/>
			</div>

			<!-- Findings panel -->
			<div class="hidden lg:flex w-80 xl:w-96 shrink-0 flex-col bg-[var(--mk-bg-panel)] border-l border-[var(--mk-border)]">
				<!-- Findings header with scan controls -->
				<div class="flex h-11 shrink-0 items-center gap-2 overflow-hidden border-b border-[var(--mk-border)] px-3">
					<ScanPanel
						{language}
						onlanguagechange={handleLanguageChange}
						onscan={handleScan}
						{scanning}
						actionEnabled={findings.length > 0 && !resultsStale}
						onaction={handleSendToAudit}
						compact
					/>
				</div>
				<FindingsList
					{error}
					{findings}
					{scanning}
					{scanCompleted}
					{resultsStale}
					{language}
					{focusedFindingId}
					onlabel={handleFindingLabel}
					onclose={handleFindingClose}
					onfocus={handleFocusFinding}
				/>
			</div>

			<div class="lg:hidden flex max-h-[42vh] shrink-0 flex-col border-t border-[var(--mk-border)] bg-[var(--mk-bg-panel)]">
				<div class="flex h-11 shrink-0 items-center justify-between border-b border-[var(--mk-border)] px-3">
					<span class="text-[10px] font-bold uppercase tracking-wider text-gray-500">
						Findings
					</span>
					<div class="flex items-center gap-2">
						<span class="rounded border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)] px-2 py-0.5 text-[10px] font-semibold text-gray-400">
							{findingCountText}
						</span>
						<button
							onclick={() => { findings = []; scanCompleted = false; resultsStale = false; currentScanId = null; error = null; focusedFindingId = null; }}
							class="p-1 rounded text-gray-600 hover:text-[var(--mk-text-soft)] hover:bg-[var(--mk-bg-elevated)] cursor-pointer"
							aria-label="Clear findings"
							title="Clear findings"
						>
							<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
								<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
							</svg>
						</button>
					</div>
				</div>
				<FindingsList
					{error}
					{findings}
					{scanning}
					{scanCompleted}
					{resultsStale}
					{language}
					{focusedFindingId}
					onlabel={handleFindingLabel}
					onclose={handleFindingClose}
					onfocus={handleFocusFinding}
				/>
			</div>
		</div>
	{#if activeTab === 'verify'}
		<div class="flex flex-1 min-h-0" style:display={activeTab === 'verify' ? 'flex' : 'none'} aria-hidden={activeTab !== 'verify'}>
			<VerifyTab
				cases={verifyCases}
				onlabel={handleCaseLabel}
				onsubmit={handleCaseSubmit}
				onclose={handleCaseClose}
			/>
		</div>
	{/if}
		<div
			class="flex flex-1 min-h-0"
			style:display={activeTab === 'audit' ? 'flex' : 'none'}
			aria-hidden={activeTab !== 'audit'}
		>
			<AuditTab auditCase={auditCase} />
		</div>
	{#if activeTab === 'knowledge'}
		<div class="flex flex-1 min-h-0" style:display={activeTab === 'knowledge' ? 'flex' : 'none'} aria-hidden={activeTab !== 'knowledge'}>
			<KnowledgeTab history={knowledgeHistory} />
		</div>
	{/if}
	{#if activeTab === 'model'}
		<div class="flex flex-1 min-h-0" style:display={activeTab === 'model' ? 'flex' : 'none'} aria-hidden={activeTab !== 'model'}>
			<ModelTab {stats} historyCount={knowledgeHistory.length} />
		</div>
	{/if}

	<!-- Status bar -->
	<StatusBar {stats} />
	</div>
</div>
