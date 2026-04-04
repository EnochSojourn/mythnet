<script>
	import { onMount, onDestroy } from 'svelte';
	import { selectedDeviceId } from '$lib/stores.js';

	let analytics = null;
	let analysis = null;
	let expanded = false;
	let expandedFinding = null;
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

	function matchingDevices(finding) {
		if (!analytics?.device_risks) return [];
		const f = finding.toLowerCase();

		// Match by risk level
		if (f.includes('critical risk level')) return analytics.device_risks.filter(d => d.risk_level === 'critical');
		if (f.includes('high risk level')) return analytics.device_risks.filter(d => d.risk_level === 'high');
		if (f.includes('low risk')) return analytics.device_risks.filter(d => d.risk_level === 'low');

		// Match by finding keyword
		if (f.includes('cve')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('cve')));
		if (f.includes('telnet')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('telnet')));
		if (f.includes('ftp')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('ftp')));
		if (f.includes('smb')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('smb')));
		if (f.includes('rdp')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('rdp')));
		if (f.includes('vnc')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('vnc')));
		if (f.includes('redis')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('redis')));
		if (f.includes('mongo')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('mongo')));
		if (f.includes('tls') || f.includes('certificate')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('tls')));
		if (f.includes('http security')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('http')));
		if (f.includes('offline')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('offline')));
		if (f.includes('unidentified')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('unidentified')));
		if (f.includes('attack surface')) return analytics.device_risks.filter(d => d.findings.some(df => df.toLowerCase().includes('attack surface')));

		return [];
	}

	function toggleFinding(finding) {
		expandedFinding = expandedFinding === finding ? null : finding;
	}

	function goToDevice(deviceId) {
		selectedDeviceId.set(deviceId);
		expandedFinding = null;
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
			<div class="px-3 pb-3 space-y-1 text-xs">
				{#each sp.critical_findings || [] as f}
					{@const devices = matchingDevices(f)}
					<div>
						<button
							class="flex items-start gap-1.5 w-full text-left group {devices.length ? 'cursor-pointer' : 'cursor-default'}"
							on:click={() => devices.length === 1 ? goToDevice(devices[0].device_id) : devices.length > 1 ? toggleFinding(f) : null}
						>
							<span class="text-red-400 shrink-0">●</span>
							<span class="text-red-300 {devices.length ? 'group-hover:text-red-100 group-hover:underline' : ''}">{f}</span>
							{#if devices.length > 1}
								<span class="text-gray-600 text-[10px] shrink-0">{devices.length} devices ›</span>
							{/if}
						</button>
						{#if expandedFinding === f && devices.length > 1}
							<div class="ml-4 mt-1 mb-1 space-y-0.5 border-l border-red-900/50 pl-2">
								{#each devices as d}
									<button class="flex items-center gap-2 w-full text-left text-[10px] py-0.5 px-1 rounded hover:bg-red-900/20 transition-colors" on:click={() => goToDevice(d.device_id)}>
										<span class="text-gray-400 font-mono">{d.ip}</span>
										<span class="text-gray-300 truncate">{d.name}</span>
										<span class="text-red-400/60 ml-auto shrink-0">{d.risk_score}</span>
									</button>
								{/each}
							</div>
						{/if}
					</div>
				{/each}
				{#each sp.warnings || [] as f}
					{@const devices = matchingDevices(f)}
					<div>
						<button
							class="flex items-start gap-1.5 w-full text-left group {devices.length ? 'cursor-pointer' : 'cursor-default'}"
							on:click={() => devices.length === 1 ? goToDevice(devices[0].device_id) : devices.length > 1 ? toggleFinding(f) : null}
						>
							<span class="text-amber-400 shrink-0">●</span>
							<span class="text-amber-300 {devices.length ? 'group-hover:text-amber-100 group-hover:underline' : ''}">{f}</span>
							{#if devices.length > 1}
								<span class="text-gray-600 text-[10px] shrink-0">{devices.length} devices ›</span>
							{/if}
						</button>
						{#if expandedFinding === f && devices.length > 1}
							<div class="ml-4 mt-1 mb-1 space-y-0.5 border-l border-amber-900/50 pl-2">
								{#each devices as d}
									<button class="flex items-center gap-2 w-full text-left text-[10px] py-0.5 px-1 rounded hover:bg-amber-900/20 transition-colors" on:click={() => goToDevice(d.device_id)}>
										<span class="text-gray-400 font-mono">{d.ip}</span>
										<span class="text-gray-300 truncate">{d.name}</span>
										<span class="text-amber-400/60 ml-auto shrink-0">{d.risk_score}</span>
									</button>
								{/each}
							</div>
						{/if}
					</div>
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
