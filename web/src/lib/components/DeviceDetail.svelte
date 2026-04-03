<script>
	import { selectedDeviceId } from '$lib/stores';
	import { getDevice } from '$lib/api';

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

	let detail = null;
	let loading = false;
	let currentId = null;

	$: if ($selectedDeviceId && $selectedDeviceId !== currentId) {
		loadDetail($selectedDeviceId);
	} else if (!$selectedDeviceId) {
		detail = null;
		currentId = null;
	}

	async function loadDetail(id) {
		currentId = id;
		loading = true;
		try {
			detail = await getDevice(id);
		} catch {
			detail = null;
		}
		loading = false;
	}

	function close() {
		selectedDeviceId.set(null);
	}

	function formatTime(ts) {
		if (!ts) return '';
		return new Date(ts).toLocaleString();
	}
</script>

{#if $selectedDeviceId}
<div class="h-full flex flex-col bg-gray-900 border-l border-gray-800">
	<div class="flex items-center justify-between px-4 py-3 border-b border-gray-800">
		<h2 class="font-semibold text-sm truncate">
			{#if detail}{detail.hostname || detail.ip}{:else}Loading...{/if}
		</h2>
		<button on:click={close} class="text-gray-500 hover:text-gray-300 ml-2 shrink-0 text-lg leading-none">&times;</button>
	</div>

	{#if loading && !detail}
		<div class="flex-1 flex items-center justify-center text-gray-500 text-sm">Loading...</div>
	{:else if detail}
	<div class="flex-1 overflow-y-auto p-4 space-y-5">
		<!-- Properties -->
		<div class="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">IP Address</div>
				<div class="font-mono text-xs">{detail.ip}</div>
			</div>
			{#if detail.mac}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">MAC</div>
				<div class="font-mono text-xs">{detail.mac}</div>
			</div>
			{/if}
			{#if detail.vendor}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Vendor</div>
				<div>{detail.vendor}</div>
			</div>
			{/if}
			{#if detail.os_guess}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">OS</div>
				<div>{detail.os_guess}</div>
			</div>
			{/if}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Type</div>
				<div style="color: {TYPE_COLORS[detail.device_type] || '#64748b'}">{detail.device_type}</div>
			</div>
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Status</div>
				<div class:text-emerald-400={detail.is_online} class:text-red-400={!detail.is_online}>
					{detail.is_online ? 'Online' : 'Offline'}
				</div>
			</div>
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">First Seen</div>
				<div class="text-xs text-gray-400">{formatTime(detail.first_seen)}</div>
			</div>
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Last Seen</div>
				<div class="text-xs text-gray-400">{formatTime(detail.last_seen)}</div>
			</div>
		</div>

		<!-- Open Ports -->
		{#if detail.ports && detail.ports.length > 0}
		<div>
			<h3 class="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
				Open Ports ({detail.ports.length})
			</h3>
			<div class="space-y-1">
				{#each detail.ports as port}
				<div class="flex items-center justify-between bg-gray-800/50 rounded px-3 py-1.5 text-sm">
					<div class="flex items-center gap-2">
						<span class="font-mono text-emerald-400 text-xs">{port.port}</span>
						<span class="text-gray-600 text-xs">/{port.protocol}</span>
					</div>
					<div class="flex items-center gap-2">
						<span class="text-gray-400 text-xs">{port.service || 'unknown'}</span>
						{#if port.service === 'http' || port.service === 'https' || port.service === 'http-proxy' || port.service === 'https-alt'}
							<a
								href="/proxy/{detail.id}/{port.port}/"
								target="_blank"
								rel="noopener"
								class="text-[10px] text-blue-400 hover:text-blue-300"
							>Open</a>
						{/if}
					</div>
				</div>
				{/each}
			</div>
		</div>
		{/if}

		<!-- Banners -->
		{#if detail.ports}
		{#each detail.ports.filter(p => p.banner) as port}
		<div>
			<h4 class="text-[11px] text-gray-500 uppercase tracking-wider mb-1">
				Banner &mdash; port {port.port}
			</h4>
			<pre class="text-[11px] bg-gray-800/50 rounded p-2.5 overflow-x-auto text-gray-300 whitespace-pre-wrap leading-relaxed">{port.banner}</pre>
		</div>
		{/each}
		{/if}
	</div>
	{/if}
</div>
{/if}
