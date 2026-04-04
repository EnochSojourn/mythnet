<script>
	import { authHeaders } from '$lib/api';

	let activeTool = 'ping';
	let target = '';
	let port = '80';
	let result = null;
	let loading = false;

	async function runTool() {
		if (!target.trim()) return;
		loading = true;
		result = null;

		try {
			let url;
			switch (activeTool) {
				case 'ping':
					url = `/api/tools/ping?target=${encodeURIComponent(target)}`;
					break;
				case 'dns':
					url = `/api/tools/dns?target=${encodeURIComponent(target)}`;
					break;
				case 'port':
					url = `/api/tools/port?target=${encodeURIComponent(target)}&port=${port}`;
					break;
				case 'subnet':
					url = `/api/subnet?cidr=${encodeURIComponent(target)}`;
					break;
			}

			const res = await fetch(url, { headers: authHeaders() });
			result = await res.json();
		} catch (e) {
			result = { error: e.message };
		}
		loading = false;
	}

	function handleKey(e) {
		if (e.key === 'Enter') runTool();
	}

	export let onClose;
</script>

<div class="h-full flex flex-col bg-gray-900 border-l border-gray-800">
	<div class="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 shrink-0">
		<span class="text-sm font-semibold">Network Tools</span>
		{#if onClose}
			<button on:click={onClose} class="text-gray-500 hover:text-gray-300 text-lg leading-none">&times;</button>
		{/if}
	</div>

	<!-- Tool tabs -->
	<div class="flex border-b border-gray-800 text-[11px]">
		{#each ['ping', 'dns', 'port', 'subnet'] as tool}
			<button
				class="flex-1 py-2 uppercase tracking-wider font-semibold transition-colors {activeTool === tool ? 'text-blue-400 border-b-2 border-blue-400' : 'text-gray-500'}"
				on:click={() => { activeTool = tool; result = null; }}
			>{tool}</button>
		{/each}
	</div>

	<!-- Input -->
	<div class="p-3 space-y-2 border-b border-gray-800">
		<input
			bind:value={target}
			on:keydown={handleKey}
			placeholder={activeTool === 'subnet' ? 'CIDR (e.g. 10.0.0.0/24)' : 'IP or hostname'}
			class="w-full bg-gray-800/50 border border-gray-700/40 rounded px-3 py-2 text-xs focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
		/>
		{#if activeTool === 'port'}
			<input
				bind:value={port}
				on:keydown={handleKey}
				placeholder="Port number"
				class="w-full bg-gray-800/50 border border-gray-700/40 rounded px-3 py-2 text-xs focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
			/>
		{/if}
		<button
			on:click={runTool}
			disabled={loading || !target.trim()}
			class="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 rounded text-xs font-medium transition-colors"
		>
			{loading ? 'Running...' : 'Run'}
		</button>
	</div>

	<!-- Results -->
	<div class="flex-1 overflow-y-auto p-3">
		{#if result}
			<pre class="text-[11px] text-gray-300 whitespace-pre-wrap leading-relaxed bg-gray-800/30 rounded p-3">{JSON.stringify(result, null, 2)}</pre>
		{:else if !loading}
			<div class="text-center text-gray-600 text-xs mt-8">
				Enter a target and click Run
			</div>
		{/if}
	</div>
</div>
