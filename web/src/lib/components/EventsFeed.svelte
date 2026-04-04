<script>
	import { onMount, onDestroy } from 'svelte';

	export let deviceId = null;
	export let limit = 30;

	let events = [];
	let interval;
	let search = '';
	let expandedId = null;

	const SEV_COLORS = {
		critical: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500' },
		warning: { bg: 'bg-amber-500/10', text: 'text-amber-400', dot: 'bg-amber-500' },
		info: { bg: 'bg-blue-500/10', text: 'text-blue-400', dot: 'bg-blue-500' },
		debug: { bg: 'bg-gray-500/10', text: 'text-gray-400', dot: 'bg-gray-600' }
	};

	const SOURCE_LABELS = {
		snmp_trap: 'SNMP Trap', syslog: 'Syslog', api_poll: 'HTTP Poll',
		port_change: 'Port Change', vuln_scan: 'CVE Scan', http_audit: 'HTTP Audit',
		tls_check: 'TLS Check', ip_conflict: 'IP Conflict', policy: 'Policy',
		ai_analysis: 'AI Analysis', snmp_poll: 'SNMP Poll', report: 'Report',
		scheduled_report: 'Scheduled Report',
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

	function relativeTime(ts) {
		const diff = (Date.now() - new Date(ts).getTime()) / 1000;
		if (diff < 60) return 'just now';
		if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
		if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
		return Math.floor(diff / 86400) + 'd ago';
	}

	function renderMd(text) {
		if (!text) return '';
		return text
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
			.replace(/```([\s\S]*?)```/g, '<pre class="bg-gray-800 rounded p-2 my-1 text-[10px] overflow-x-auto whitespace-pre-wrap">$1</pre>')
			.replace(/`([^`]+)`/g, '<code class="bg-gray-800 px-1 rounded text-[10px]">$1</code>')
			.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
			.replace(/^### (.+)$/gm, '<div class="font-semibold mt-2 text-[11px] text-blue-300">$1</div>')
			.replace(/^## (.+)$/gm, '<div class="font-semibold mt-2 text-xs text-blue-200">$1</div>')
			.replace(/^\| (.+)$/gm, (m) => '<div class="font-mono text-[10px] text-gray-400">' + m + '</div>')
			.replace(/^- (.+)$/gm, '<div class="ml-2 text-[11px]">• $1</div>')
			.replace(/^> (.+)$/gm, '<div class="border-l-2 border-amber-500 pl-2 text-amber-300 text-[11px] my-0.5">$1</div>')
			.replace(/\n/g, '<br>');
	}

	function toggle(id) {
		expandedId = expandedId === id ? null : id;
	}

	onMount(() => { refresh(); interval = setInterval(refresh, 8000); });
	onDestroy(() => clearInterval(interval));
</script>

<div class="overflow-y-auto">
	<div class="px-3 py-2 border-b border-gray-800/30">
		<input
			bind:value={search}
			on:input={refresh}
			placeholder="Search events..."
			class="w-full bg-gray-800/50 border border-gray-700/40 rounded px-2.5 py-1.5 text-xs focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600"
		/>
	</div>
	{#each events as event (event.id)}
		{@const sev = SEV_COLORS[event.severity] || SEV_COLORS.info}
		<button class="w-full text-left px-3 py-2.5 border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors" on:click={() => toggle(event.id)}>
			<div class="flex items-start gap-2">
				<span class="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 {sev.dot}"></span>
				<div class="flex-1 min-w-0">
					<div class="flex items-center gap-2 mb-0.5">
						<span class="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded {sev.bg} {sev.text}">
							{event.severity}
						</span>
						<span class="text-[10px] text-gray-600">
							{SOURCE_LABELS[event.source] || event.source}
						</span>
						<span class="text-[10px] text-gray-700 ml-auto shrink-0">
							{relativeTime(event.received_at)}
						</span>
					</div>
					<div class="text-xs text-gray-300" class:truncate={expandedId !== event.id}>{event.title}</div>
				</div>
			</div>
		</button>
		<!-- Expanded: full Markdown body -->
		{#if expandedId === event.id}
			<div class="px-4 py-3 bg-gray-800/20 border-b border-gray-800/30">
				{#if event.tags}
					<div class="flex gap-1 flex-wrap mb-2">
						{#each event.tags.split(',') as t}
							<span class="text-[9px] bg-gray-700/50 text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
						{/each}
					</div>
				{/if}
				<div class="text-[11px] leading-relaxed">
					{@html renderMd(event.body_md)}
				</div>
			</div>
		{/if}
	{/each}
	{#if events.length === 0}
		<div class="p-4 text-gray-600 text-xs text-center">
			No events yet — waiting for telemetry data
		</div>
	{/if}
</div>
