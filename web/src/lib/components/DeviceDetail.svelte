<script>
	import { selectedDeviceId } from '$lib/stores';
	import { getDevice } from '$lib/api';

	let notes = '';
	let notesSaved = false;
	let notesTimer;

	async function loadNotes(id) {
		try {
			const res = await fetch(`/api/devices/${id}/notes`, { headers: authHeaders() });
			const data = await res.json();
			notes = data.notes || '';
		} catch { notes = ''; }
	}

	function saveNotes() {
		if (!currentId) return;
		clearTimeout(notesTimer);
		notesTimer = setTimeout(async () => {
			await fetch(`/api/devices/${currentId}/notes`, {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json', ...authHeaders() },
				body: JSON.stringify({ notes })
			});
			notesSaved = true;
			setTimeout(() => notesSaved = false, 2000);
		}, 500);
	}

	async function addTag() {
		const t = tagInput.trim().toLowerCase();
		if (!t || !currentId || tags.includes(t)) return;
		tags = [...tags, t];
		tagInput = '';
		await fetch(`/api/devices/${currentId}/tags`, {
			method: 'PUT',
			headers: { 'Content-Type': 'application/json', ...authHeaders() },
			body: JSON.stringify(tags)
		});
	}

	async function removeTag(tag) {
		tags = tags.filter(t => t !== tag);
		await fetch(`/api/devices/${currentId}/tags`, {
			method: 'PUT',
			headers: { 'Content-Type': 'application/json', ...authHeaders() },
			body: JSON.stringify(tags)
		});
	}

	async function wakeDevice() {
		if (!currentId) return;
		try {
			await fetch(`/api/devices/${currentId}/wake`, {
				method: 'POST', headers: authHeaders()
			});
		} catch {}
	}

	function authHeaders() {
		const creds = localStorage.getItem('mythnet_creds');
		return creds ? { 'Authorization': 'Basic ' + creds } : {};
	}

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
	let uptime = null;
	let latency = [];
	let tags = [];
	let tagInput = '';
	let loading = false;
	let currentId = null;

	$: if ($selectedDeviceId && $selectedDeviceId !== currentId) {
		loadDetail($selectedDeviceId);
	} else if (!$selectedDeviceId) {
		detail = null;
		uptime = null;
		currentId = null;
	}

	async function loadDetail(id) {
		currentId = id;
		loading = true;
		try {
			const resp = await getDevice(id);
			if (resp.device) {
				detail = resp.device;
				uptime = resp.uptime || null;
				latency = resp.latency || [];
				if (resp.notes) notes = resp.notes;
			tags = resp.tags || [];
			} else {
				detail = resp;
				uptime = null;
				latency = [];
			}
		} catch {
			detail = null;
			uptime = null;
			latency = [];
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
				<div class="flex items-center gap-2">
					<span class:text-emerald-400={detail.is_online} class:text-red-400={!detail.is_online}>
						{detail.is_online ? 'Online' : 'Offline'}
					</span>
					{#if !detail.is_online && detail.mac}
						<button
							on:click={wakeDevice}
							class="text-[10px] bg-amber-600/20 text-amber-400 hover:bg-amber-600/30 px-1.5 py-0.5 rounded transition-colors"
						>Wake</button>
					{/if}
				</div>
			</div>
			{#if uptime}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Uptime (24h)</div>
				<div class="text-xs font-mono" class:text-emerald-400={uptime.uptime_pct >= 99} class:text-amber-400={uptime.uptime_pct < 99 && uptime.uptime_pct >= 90} class:text-red-400={uptime.uptime_pct < 90}>
					{uptime.uptime_pct.toFixed(1)}%
				</div>
			</div>
			{/if}
			{#if latency.length > 0}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Latency</div>
				<div class="text-xs font-mono" class:text-emerald-400={latency[0].rtt_ms < 10} class:text-amber-400={latency[0].rtt_ms >= 10 && latency[0].rtt_ms < 100} class:text-red-400={latency[0].rtt_ms >= 100}>
					{latency[0].rtt_ms.toFixed(1)} ms
				</div>
			</div>
			{/if}
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">First Seen</div>
				<div class="text-xs text-gray-400">{formatTime(detail.first_seen)}</div>
			</div>
			<div>
				<div class="text-[11px] text-gray-500 uppercase tracking-wider mb-0.5">Last Seen</div>
				<div class="text-xs text-gray-400">{formatTime(detail.last_seen)}</div>
			</div>
		</div>

		<!-- Uptime Timeline -->
		{#if uptime && uptime.transitions && uptime.transitions.length > 0}
		<div>
			<h3 class="text-[11px] text-gray-500 uppercase tracking-wider mb-2">State History</h3>
			<div class="space-y-1">
				{#each uptime.transitions.slice(-8) as t}
				<div class="flex items-center gap-2 text-xs">
					<span class="w-1.5 h-1.5 rounded-full" class:bg-emerald-500={t.state === 'online'} class:bg-red-500={t.state === 'offline'}></span>
					<span class:text-emerald-400={t.state === 'online'} class:text-red-400={t.state === 'offline'}>{t.state}</span>
					<span class="text-gray-600 ml-auto">{formatTime(t.changed_at)}</span>
				</div>
				{/each}
			</div>
		</div>
		{/if}

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
		<!-- AI Device Intelligence -->
		{#if notes}
		<div class="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
			<h3 class="text-[11px] text-blue-400 uppercase tracking-wider font-semibold mb-1.5">AI Intelligence</h3>
			<div class="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{notes}</div>
		</div>
		{/if}

		<!-- Device Events -->
		{#if detail}
		<div>
			<h3 class="text-[11px] text-gray-500 uppercase tracking-wider mb-2">Recent Activity</h3>
			{#await fetch(`/api/events?device_id=${detail.id}&limit=5`, {headers: authHeaders()}).then(r => r.json()) then events}
				{#each events as e}
					<div class="flex items-start gap-2 mb-1.5 text-[11px]">
						<span class="w-1.5 h-1.5 rounded-full mt-1 shrink-0" class:bg-red-500={e.severity==='critical'} class:bg-amber-500={e.severity==='warning'} class:bg-blue-500={e.severity==='info'}></span>
						<div class="flex-1 min-w-0">
							<div class="text-gray-300 truncate">{e.title}</div>
							<div class="text-gray-600">{e.source} · {new Date(e.received_at).toLocaleString()}</div>
						</div>
					</div>
				{/each}
				{#if events.length === 0}
					<div class="text-[11px] text-gray-600">No events for this device</div>
				{/if}
			{/await}
		</div>
		{/if}

		<!-- Tags -->
		<div>
			<h3 class="text-[11px] text-gray-500 uppercase tracking-wider mb-2">Tags</h3>
			<div class="flex flex-wrap gap-1.5 mb-2">
				{#each tags as tag}
					<span class="inline-flex items-center gap-1 bg-blue-500/15 text-blue-400 text-[11px] px-2 py-0.5 rounded-full">
						{tag}
						<button on:click={() => removeTag(tag)} class="hover:text-white text-[10px] ml-0.5">&times;</button>
					</span>
				{/each}
			</div>
			<div class="flex gap-1">
				<input
					bind:value={tagInput}
					on:keydown={(e) => { if (e.key === 'Enter') addTag(); }}
					placeholder="Add tag..."
					class="flex-1 bg-gray-800/40 border border-gray-700/40 rounded px-2 py-1 text-[11px] focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
				/>
				<button on:click={addTag} class="text-[11px] text-blue-400 hover:text-blue-300 px-2">Add</button>
			</div>
		</div>

		<!-- Notes -->
		<div>
			<div class="flex items-center justify-between mb-1">
				<h3 class="text-[11px] text-gray-500 uppercase tracking-wider">Notes</h3>
				{#if notesSaved}
					<span class="text-[10px] text-emerald-400">Saved</span>
				{/if}
			</div>
			<textarea
				bind:value={notes}
				on:input={saveNotes}
				placeholder="Add notes about this device..."
				class="w-full bg-gray-800/40 border border-gray-700/40 rounded p-2 text-xs text-gray-300 resize-y min-h-[60px] focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
				rows="3"
			></textarea>
		</div>
	</div>
	{/if}
</div>
{/if}
