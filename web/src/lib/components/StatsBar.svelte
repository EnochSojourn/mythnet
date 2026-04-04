<script>
	import { onMount } from 'svelte';
	import { stats } from '$lib/stores';
	import Sparkline from './Sparkline.svelte';

	let onlineHistory = [];
	let eventHistory = [];
	let latencyHistory = [];

	async function loadSnapshots() {
		try {
			const res = await fetch('/api/snapshots?hours=24');
			if (!res.ok) return;
			const snaps = await res.json();
			onlineHistory = snaps.map(s => s.online_devices);
			eventHistory = snaps.map(s => s.total_events);
			latencyHistory = snaps.map(s => s.avg_latency);
		} catch {}
	}

	onMount(() => {
		loadSnapshots();
		const iv = setInterval(loadSnapshots, 60000);
		return () => clearInterval(iv);
	});
</script>

<div class="grid grid-cols-2 gap-2 p-3">
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="flex items-end justify-between">
			<div class="text-xl font-bold tabular-nums">{$stats.total_devices}</div>
			<Sparkline data={onlineHistory} color="#64748b" />
		</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Devices</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="flex items-end justify-between">
			<div class="text-xl font-bold tabular-nums text-emerald-400">{$stats.online_devices}</div>
			<Sparkline data={onlineHistory} color="#34d399" />
		</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Online</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="flex items-end justify-between">
			<div class="text-xl font-bold tabular-nums text-blue-400">{$stats.total_ports}</div>
			<Sparkline data={latencyHistory} color="#60a5fa" />
		</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Avg Latency</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="flex items-end justify-between">
			<div class="text-xl font-bold tabular-nums text-violet-400">{$stats.total_events || 0}</div>
			<Sparkline data={eventHistory} color="#a78bfa" />
		</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Events</div>
	</div>
</div>
