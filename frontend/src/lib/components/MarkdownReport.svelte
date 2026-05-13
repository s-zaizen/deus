<script lang="ts">
	import { parseMarkdown, type InlineNode } from '$lib/markdown';

	let { source, compact = false }: { source: string; compact?: boolean } = $props();

	const blocks = $derived(parseMarkdown(source));
</script>

{#snippet inlineNodes(nodes: InlineNode[])}
	{#each nodes as node}
		{#if node.type === 'text'}
			{node.text}
		{:else if node.type === 'strong'}
			<strong class="font-semibold text-[var(--mk-text)]">{@render inlineNodes(node.children)}</strong>
		{:else if node.type === 'code'}
			<code class="rounded bg-[var(--mk-border)] px-1 py-0.5 font-mono text-[11px] text-[var(--mk-text-soft)]">{node.text}</code>
		{/if}
	{/each}
{/snippet}

<div class={compact ? 'markdown-report text-xs leading-relaxed text-gray-300' : 'markdown-report text-sm leading-7 text-gray-300'}>
	{#each blocks as block}
		{#if block.type === 'heading'}
			{#if block.level === 1}
				<h1 class={compact ? 'mb-3 mt-4 border-b border-[var(--mk-border)] pb-2 text-base font-bold text-[var(--mk-text)] first:mt-0' : 'mb-4 mt-6 border-b border-[var(--mk-border)] pb-2 text-lg font-bold text-[var(--mk-text)] first:mt-0'}>
					{@render inlineNodes(block.children)}
				</h1>
			{:else if block.level === 2}
				<h2 class={compact ? 'mb-2 mt-5 border-t border-[var(--mk-border)] pt-4 text-sm font-bold text-[var(--mk-text)] first:mt-0 first:border-t-0 first:pt-0' : 'mb-3 mt-7 border-t border-[var(--mk-border)] pt-5 text-base font-bold text-[var(--mk-text)] first:mt-0 first:border-t-0 first:pt-0'}>
					{@render inlineNodes(block.children)}
				</h2>
			{:else if block.level === 3}
				<h3 class={compact ? 'mb-2 mt-4 border-l-2 border-[var(--mk-copper)] pl-2 text-[11px] font-bold uppercase tracking-wider text-[var(--mk-text-soft)]' : 'mb-2 mt-5 border-l-2 border-[var(--mk-copper)] pl-2.5 text-xs font-bold uppercase tracking-wider text-[var(--mk-text-soft)]'}>
					{@render inlineNodes(block.children)}
				</h3>
			{:else}
				<h4 class={compact ? 'mb-1.5 mt-3 text-xs font-semibold text-violet-200' : 'mb-2 mt-4 text-sm font-semibold text-violet-200'}>
					{@render inlineNodes(block.children)}
				</h4>
			{/if}
		{:else if block.type === 'paragraph'}
			<p class={compact ? 'mb-3 text-gray-300' : 'mb-4 text-gray-300'}>
				{@render inlineNodes(block.children)}
			</p>
		{:else if block.type === 'code'}
			<div class={compact ? 'mb-3 overflow-x-auto rounded-md border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]' : 'mb-4 overflow-x-auto rounded-md border border-[var(--mk-border)] bg-[var(--mk-bg-elevated)]'}>
				{#if block.language}
					<div class="border-b border-[var(--mk-border)] px-3 py-1 text-[10px] font-mono uppercase text-gray-600">
						{block.language}
					</div>
				{/if}
				<pre class="whitespace-pre p-3 font-mono text-xs text-gray-300"><code>{block.text}</code></pre>
			</div>
		{:else if block.type === 'list'}
			{#if block.ordered}
				<ol class={compact ? 'mb-3 list-decimal space-y-1 pl-5' : 'mb-4 list-decimal space-y-1.5 pl-5'}>
					{#each block.items as item}
						<li>{@render inlineNodes(item)}</li>
					{/each}
				</ol>
			{:else}
				<ul class={compact ? 'mb-3 list-disc space-y-1 pl-5' : 'mb-4 list-disc space-y-1.5 pl-5'}>
					{#each block.items as item}
						<li>{@render inlineNodes(item)}</li>
					{/each}
				</ul>
			{/if}
		{:else if block.type === 'table'}
			<div class={compact ? 'mb-3 overflow-x-auto rounded-md border border-[var(--mk-border)]' : 'mb-4 overflow-x-auto rounded-md border border-[var(--mk-border)]'}>
				<table class="min-w-full border-collapse text-left text-xs">
					<thead class="bg-[var(--mk-bg-elevated)] text-[10px] uppercase tracking-wider text-gray-500">
						<tr>
							{#each block.headers as header}
								<th class="border-b border-gray-800 px-3 py-2 font-semibold">
									{@render inlineNodes(header)}
								</th>
							{/each}
						</tr>
					</thead>
					<tbody>
						{#each block.rows as row}
							<tr class="border-b border-[var(--mk-border)] last:border-0">
								{#each row as cell}
									<td class="align-top px-3 py-2 text-gray-300">
										{@render inlineNodes(cell)}
									</td>
								{/each}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/each}
</div>
