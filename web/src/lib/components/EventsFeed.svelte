<script>
	import { onMount, onDestroy } from 'svelte';
	import { getEvents } from '$lib/api';

	export let deviceId = null;
	export let limit = 30;

	let events = [];
	let interval;
	let search = '';

	const SEV_COLORS = {
		critical: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500' },
		warning: { bg: 'bg-amber-500/10', text: 'text-amber-400', dot: 'bg-amber-500' },
		info: { bg: 'bg-blue-500/10', text: 'text-blue-400', dot: 'bg-blue-500' },
		debug: { bg: 'bg-gray-500/10', text: 'text-gray-400', dot: 'bg-gray-600' }
	};

	const SOURCE_LABELS = {
		snmp_trap: 'SNMP',
		syslog: 'Syslog',
		api_poll: 'HTTP'
	};

	async function refresh() {
		try {
			const params = new URLSearchParams();
			params.set('limit', limit);
			if (deviceId) params.set('device_id', deviceId);
			if (search.trim()) params.set('q', search.trim());
			const res = await fetch(`/api/events?${params}`);
			events = await res.json();
		} catch {}
	}

	function handleSearch() {
		refresh();
	}

	function relativeTime(ts) {
		const diff = (Date.now() - new Date(ts).getTime()) / 1000;
		if (diff < 60) return 'just now';
		if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
		if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
		return Math.floor(diff / 86400) + 'd ago';
	}

	onMount(() => {
		refresh();
		interval = setInterval(refresh, 8000);
	});

	onDestroy(() => {
		if (interval) clearInterval(interval);
	});
</script>

<div class="overflow-y-auto">
	<div class="px-3 py-2 border-b border-gray-800/30">
		<input
			bind:value={search}
			on:input={handleSearch}
			placeholder="Search events..."
			class="w-full bg-gray-800/50 border border-gray-700/40 rounded px-2.5 py-1.5 text-xs focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
		/>
	</div>
	{#each events as event (event.id)}
		{@const sev = SEV_COLORS[event.severity] || SEV_COLORS.info}
		<div class="px-3 py-2.5 border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
			<div class="flex items-start gap-2">
				<span class="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 {sev.dot}"></span>
				<div class="flex-1 min-w-0">
					<div class="flex items-center gap-2 mb-0.5">
						<span class="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded {sev.bg} {sev.text}">
							{event.severity}
						</span>
						<span class="text-[10px] text-gray-600 font-mono">
							{SOURCE_LABELS[event.source] || event.source}
						</span>
						<span class="text-[10px] text-gray-700 ml-auto shrink-0">
							{relativeTime(event.received_at)}
						</span>
					</div>
					<div class="text-xs text-gray-300 truncate">{event.title}</div>
				</div>
			</div>
		</div>
	{/each}
	{#if events.length === 0}
		<div class="p-4 text-gray-600 text-xs text-center">
			No events yet — waiting for telemetry data
		</div>
	{/if}
</div>
