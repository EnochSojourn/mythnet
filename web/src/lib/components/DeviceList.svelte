<script>
	import { devices, selectedDeviceId } from '$lib/stores';

	const TYPE_COLORS = {
		'Network Equipment': '#3b82f6',
		'Server': '#22c55e',
		'Endpoint': '#64748b',
		'IoT': '#a855f7',
		'IP Camera': '#ef4444',
		'AV Equipment': '#06b6d4',
		'Firewall': '#f97316',
		'NAS': '#14b8a6',
		'Printer': '#eab308',
		'Virtual Machine': '#6366f1',
		'Media Player': '#ec4899',
		'SBC': '#84cc16'
	};

	function toggle(id) {
		selectedDeviceId.update(cur => cur === id ? null : id);
	}
</script>

<div class="overflow-y-auto">
	{#each $devices as device (device.id)}
		<button
			class="w-full text-left px-3 py-2.5 border-b border-gray-800/40 transition-colors hover:bg-gray-800/60"
			class:bg-gray-800={$selectedDeviceId === device.id}
			on:click={() => toggle(device.id)}
		>
			<div class="flex items-center gap-2">
				<span
					class="w-2 h-2 rounded-full shrink-0"
					class:bg-emerald-500={device.is_online}
					class:bg-red-500={!device.is_online}
				></span>
				<span class="text-sm font-medium truncate">{device.hostname || device.ip}</span>
				<span
					class="ml-auto text-[10px] font-medium px-1.5 py-0.5 rounded"
					style="background: {TYPE_COLORS[device.device_type] || '#64748b'}20; color: {TYPE_COLORS[device.device_type] || '#64748b'}"
				>
					{device.device_type || 'Unknown'}
				</span>
			</div>
			<div class="text-xs text-gray-500 mt-0.5 ml-4 font-mono">
				{device.ip}
				{#if device.vendor}<span class="font-sans"> · {device.vendor}</span>{/if}
			</div>
		</button>
	{/each}
	{#if $devices.length === 0}
		<div class="p-6 text-gray-600 text-sm text-center">
			No devices discovered yet
		</div>
	{/if}
</div>
