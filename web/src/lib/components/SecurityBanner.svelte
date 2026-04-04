<script>
	import { onMount, onDestroy } from 'svelte';

	let analytics = null;
	let analysis = null;
	let expanded = false;
	let interval;

	async function load() {
		try {
			const [a, r] = await Promise.all([
				fetch('/api/analytics').then(r => r.ok ? r.json() : null),
				fetch('/api/analysis').then(r => r.ok ? r.json() : null),
			]);
			analytics = a;
			analysis = r;
		} catch {}
	}

	function renderMd(text) {
		if (!text) return '';
		return text
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
			.replace(/```([\s\S]*?)```/g, '<pre class="bg-gray-800 rounded p-2 my-1 text-[10px] overflow-x-auto">$1</pre>')
			.replace(/`([^`]+)`/g, '<code class="bg-gray-800 px-1 rounded text-[10px]">$1</code>')
			.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
			.replace(/^### (.+)$/gm, '<div class="font-semibold mt-2 text-xs text-blue-300">$1</div>')
			.replace(/^## (.+)$/gm, '<div class="font-semibold mt-2 text-sm text-blue-200">$1</div>')
			.replace(/^- (.+)$/gm, '<div class="ml-2 text-xs">• $1</div>')
			.replace(/^> (.+)$/gm, '<div class="border-l-2 border-amber-500 pl-2 text-amber-300 text-xs my-1">$1</div>')
			.replace(/\n/g, '<br>');
	}

	onMount(() => { load(); interval = setInterval(load, 30000); });
	onDestroy(() => clearInterval(interval));
</script>

{#if analytics}
	{@const sp = analytics.security_posture}
	<div class="border-b border-gray-800/60">
		<!-- Grade bar -->
		<button class="w-full px-3 py-2.5 flex items-center gap-3 hover:bg-gray-800/40 transition-colors" on:click={() => expanded = !expanded}>
			<div class="text-2xl font-black {sp.score >= 80 ? 'text-emerald-400' : sp.score >= 60 ? 'text-amber-400' : 'text-red-400'}">{sp.grade}</div>
			<div class="flex-1 text-left">
				<div class="text-xs font-semibold">Security: {sp.score}/100</div>
				<div class="text-[10px] text-gray-500">
					{analytics.risk_distribution.critical} critical · {analytics.risk_distribution.high || 0} high · {analytics.risk_distribution.low} clean
				</div>
			</div>
			<svg class="w-3 h-3 text-gray-600 transition-transform {expanded ? 'rotate-180' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M19 9l-7 7-7-7"/></svg>
		</button>

		<!-- Expanded findings -->
		{#if expanded}
			<div class="px-3 pb-3 space-y-1.5 text-xs">
				{#each sp.critical_findings || [] as f}
					<div class="flex items-start gap-1.5"><span class="text-red-400 shrink-0">●</span><span class="text-red-300">{f}</span></div>
				{/each}
				{#each sp.warnings || [] as f}
					<div class="flex items-start gap-1.5"><span class="text-amber-400 shrink-0">●</span><span class="text-amber-300">{f}</span></div>
				{/each}
				{#each sp.recommendations || [] as r}
					<div class="flex items-start gap-1.5"><span class="text-blue-400 shrink-0">→</span><span class="text-gray-300">{r}</span></div>
				{/each}

				<!-- Latest AI analysis -->
				{#if analysis?.analysis}
					<div class="mt-2 pt-2 border-t border-gray-800/50">
						<div class="text-[10px] text-blue-400 font-semibold uppercase tracking-wider mb-1">AI Analysis</div>
						<div class="text-[11px] leading-relaxed max-h-60 overflow-y-auto">
							{@html renderMd(analysis.analysis)}
						</div>
					</div>
				{:else}
					<div class="text-[10px] text-gray-600 italic mt-1">AI analysis will generate after the next scan...</div>
				{/if}
			</div>
		{/if}
	</div>
{/if}
