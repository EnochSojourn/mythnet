<script>
	import { stats } from '$lib/stores';
</script>

<div class="grid grid-cols-2 gap-2 p-3">
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="text-xl font-bold tabular-nums">{$stats.total_devices}</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Devices</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="text-xl font-bold tabular-nums text-emerald-400">{$stats.online_devices}</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Online</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="text-xl font-bold tabular-nums text-blue-400">{$stats.total_ports}</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Open Ports</div>
	</div>
	<div class="bg-gray-800/60 rounded-lg p-3">
		<div class="text-xl font-bold tabular-nums text-violet-400">{$stats.total_events || 0}</div>
		<div class="text-[11px] text-gray-500 uppercase tracking-wider">Events</div>
	</div>
</div>
