<script>
	import { onMount } from 'svelte';
	import { authHeaders } from '$lib/api';

	export let onClose;

	let tab = 'analytics';
	let analytics = null;
	let policies = [];
	let rules = [];
	let audit = [];
	let settings = null;
	let loading = true;

	// Policy form
	let policyName = '';
	let policyMatchType = '';
	let policyMatchTag = '';
	let policyRequirePort = '';
	let policyForbidPort = '';
	let policyRequireOnline = false;

	// Rule form
	let ruleName = '';
	let rulePattern = '';
	let ruleSource = '';
	let ruleSeverity = '';
	let ruleTag = '';

	async function fetchJSON(path) {
		const res = await fetch(path, { headers: authHeaders() });
		return res.json();
	}

	async function loadAll() {
		loading = true;
		[analytics, policies, rules, audit, settings] = await Promise.all([
			fetchJSON('/api/analytics'),
			fetchJSON('/api/policies'),
			fetchJSON('/api/rules'),
			fetchJSON('/api/audit'),
			fetchJSON('/api/settings'),
		]);
		loading = false;
	}

	async function createPolicy() {
		await fetch('/api/policies', {
			method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
			body: JSON.stringify({
				name: policyName, match_type: policyMatchType, match_tag: policyMatchTag,
				require_port: parseInt(policyRequirePort) || 0,
				forbid_port: parseInt(policyForbidPort) || 0,
				require_online: policyRequireOnline, severity: 'warning', enabled: true
			})
		});
		policyName = ''; policyMatchType = ''; policyMatchTag = '';
		policyRequirePort = ''; policyForbidPort = '';
		policies = await fetchJSON('/api/policies');
	}

	async function createRule() {
		await fetch('/api/rules', {
			method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
			body: JSON.stringify({
				name: ruleName, pattern: rulePattern, source_match: ruleSource,
				set_severity: ruleSeverity, add_tag: ruleTag, enabled: true
			})
		});
		ruleName = ''; rulePattern = ''; ruleSource = ''; ruleSeverity = ''; ruleTag = '';
		rules = await fetchJSON('/api/rules');
	}

	onMount(loadAll);

	const sevColor = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-amber-400', low: 'text-emerald-400' };
	const sevBg = { critical: 'bg-red-500/10', high: 'bg-orange-500/10', medium: 'bg-amber-500/10', low: 'bg-emerald-500/10' };
</script>

<div class="fixed inset-0 z-50 bg-gray-950 overflow-hidden flex flex-col">
	<!-- Header -->
	<div class="flex items-center justify-between px-6 py-3 bg-gray-900 border-b border-gray-800 shrink-0">
		<div class="flex items-center gap-4">
			<h2 class="text-lg font-bold"><span class="text-blue-400">Myth</span>Net Admin</h2>
			<div class="flex gap-1 text-xs">
				{#each ['analytics', 'policies', 'rules', 'audit', 'settings'] as t}
					<button
						class="px-3 py-1.5 rounded-md transition-colors capitalize {tab === t ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'}"
						on:click={() => tab = t}
					>{t}</button>
				{/each}
			</div>
		</div>
		<button on:click={onClose} class="text-gray-500 hover:text-white text-xl">&times;</button>
	</div>

	<!-- Content -->
	<div class="flex-1 overflow-y-auto p-6">
		{#if loading}
			<div class="text-gray-500 text-center mt-20">Loading...</div>
		{:else if tab === 'analytics' && analytics}
			<!-- Security Posture -->
			<div class="max-w-6xl mx-auto space-y-6">
				<div class="grid grid-cols-4 gap-4">
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<div class="text-4xl font-bold {analytics.security_posture.score >= 80 ? 'text-emerald-400' : analytics.security_posture.score >= 60 ? 'text-amber-400' : 'text-red-400'}">
							{analytics.security_posture.grade}
						</div>
						<div class="text-sm text-gray-500 mt-1">Security Grade</div>
						<div class="text-xs text-gray-600 mt-0.5">{analytics.security_posture.score}/100</div>
					</div>
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<div class="text-4xl font-bold">{analytics.total_devices}</div>
						<div class="text-sm text-gray-500 mt-1">Total Devices</div>
					</div>
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<div class="text-4xl font-bold text-red-400">{analytics.risk_distribution.critical + analytics.risk_distribution.high}</div>
						<div class="text-sm text-gray-500 mt-1">At-Risk Devices</div>
					</div>
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<div class="text-4xl font-bold text-emerald-400">{analytics.risk_distribution.low}</div>
						<div class="text-sm text-gray-500 mt-1">Low Risk</div>
					</div>
				</div>

				<!-- Findings -->
				<div class="grid grid-cols-2 gap-4">
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<h3 class="text-sm font-semibold text-gray-300 mb-3">Findings & Recommendations</h3>
						{#each analytics.security_posture.critical_findings || [] as f}
							<div class="flex items-start gap-2 mb-2 text-sm"><span class="text-red-400 shrink-0">●</span> <span class="text-red-300">{f}</span></div>
						{/each}
						{#each analytics.security_posture.warnings || [] as f}
							<div class="flex items-start gap-2 mb-2 text-sm"><span class="text-amber-400 shrink-0">●</span> <span class="text-amber-300">{f}</span></div>
						{/each}
						{#each analytics.security_posture.positives || [] as f}
							<div class="flex items-start gap-2 mb-2 text-sm"><span class="text-emerald-400 shrink-0">●</span> <span class="text-emerald-300">{f}</span></div>
						{/each}
					</div>
					<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
						<h3 class="text-sm font-semibold text-gray-300 mb-3">Action Items</h3>
						{#each analytics.security_posture.recommendations || [] as r, i}
							<div class="flex items-start gap-2 mb-2 text-sm">
								<span class="text-blue-400 shrink-0 font-mono text-xs">{i+1}.</span>
								<span class="text-gray-300">{r}</span>
							</div>
						{/each}
					</div>
				</div>

				<!-- Device Risk Table -->
				<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
					<h3 class="text-sm font-semibold text-gray-300 mb-3">Device Risk Assessment</h3>
					<table class="w-full text-sm">
						<thead><tr class="text-gray-500 text-xs uppercase tracking-wider border-b border-gray-800">
							<th class="text-left py-2 px-2">Device</th><th class="text-left py-2">IP</th>
							<th class="text-left py-2">Risk</th><th class="text-left py-2">Level</th>
							<th class="text-left py-2">Findings</th>
						</tr></thead>
						<tbody>
							{#each analytics.device_risks.sort((a,b) => b.risk_score - a.risk_score) as r}
								<tr class="border-b border-gray-800/50 hover:bg-gray-800/30">
									<td class="py-2 px-2 font-medium">{r.name}</td>
									<td class="py-2 font-mono text-xs text-gray-400">{r.ip}</td>
									<td class="py-2">
										<div class="flex items-center gap-2">
											<div class="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
												<div class="h-full rounded-full {r.risk_score >= 50 ? 'bg-red-500' : r.risk_score >= 30 ? 'bg-orange-500' : r.risk_score >= 15 ? 'bg-amber-500' : 'bg-emerald-500'}" style="width:{r.risk_score}%"></div>
											</div>
											<span class="text-xs text-gray-400">{r.risk_score}</span>
										</div>
									</td>
									<td class="py-2"><span class="text-xs px-2 py-0.5 rounded-full {sevBg[r.risk_level]} {sevColor[r.risk_level]}">{r.risk_level}</span></td>
									<td class="py-2 text-xs text-gray-500">{r.findings.filter(f => f !== 'No issues found').join('; ') || '—'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>

				<!-- Subnet Analysis -->
				<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
					<h3 class="text-sm font-semibold text-gray-300 mb-3">Subnet Analysis</h3>
					{#each analytics.subnets as s}
						<div class="mb-4 p-3 bg-gray-800/30 rounded-lg">
							<div class="flex items-center justify-between mb-2">
								<span class="font-mono text-sm text-blue-400">{s.subnet}</span>
								<span class="text-xs text-gray-500">{s.device_count} devices, avg risk {s.avg_risk}</span>
							</div>
							<div class="flex gap-2 flex-wrap mb-2">
								{#each Object.entries(s.type_breakdown) as [type, count]}
									<span class="text-[11px] bg-gray-700/50 px-2 py-0.5 rounded">{type}: {count}</span>
								{/each}
							</div>
							{#each s.findings || [] as f}
								<div class="text-xs text-amber-400 mt-1">⚠ {f}</div>
							{/each}
						</div>
					{/each}
				</div>
			</div>

		{:else if tab === 'policies'}
			<div class="max-w-4xl mx-auto space-y-4">
				<h3 class="text-lg font-semibold">Network Policies</h3>
				<p class="text-sm text-gray-500">Define expected network state. Violations generate alerts on every scan.</p>

				<!-- Create policy form -->
				<div class="bg-gray-900 rounded-xl p-5 border border-gray-800 space-y-3">
					<div class="grid grid-cols-2 gap-3">
						<input bind:value={policyName} placeholder="Policy name" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={policyMatchType} placeholder="Match device type (e.g. Server)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={policyMatchTag} placeholder="Match tag (e.g. production)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={policyRequirePort} placeholder="Require port (e.g. 22)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={policyForbidPort} placeholder="Forbid port (e.g. 23)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<label class="flex items-center gap-2 text-sm text-gray-400">
							<input type="checkbox" bind:checked={policyRequireOnline} class="rounded" /> Require online
						</label>
					</div>
					<button on:click={createPolicy} disabled={!policyName} class="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 rounded text-sm">Create Policy</button>
				</div>

				<!-- Existing policies -->
				{#each policies as p}
					<div class="bg-gray-900 rounded-lg p-4 border border-gray-800 flex items-center justify-between">
						<div>
							<div class="font-medium text-sm">{p.name}</div>
							<div class="text-xs text-gray-500 mt-0.5">
								{p.match_type ? `Type: ${p.match_type}` : ''}{p.match_tag ? ` Tag: ${p.match_tag}` : ''}
								{p.require_port ? ` Require port ${p.require_port}` : ''}{p.forbid_port ? ` Forbid port ${p.forbid_port}` : ''}
							</div>
						</div>
						<span class="text-xs {p.enabled ? 'text-emerald-400' : 'text-gray-600'}">{p.enabled ? 'Active' : 'Disabled'}</span>
					</div>
				{/each}
				{#if policies.length === 0}<div class="text-gray-600 text-sm">No policies defined yet.</div>{/if}
			</div>

		{:else if tab === 'rules'}
			<div class="max-w-4xl mx-auto space-y-4">
				<h3 class="text-lg font-semibold">Custom Event Rules</h3>
				<p class="text-sm text-gray-500">Pattern-match incoming events and re-classify severity or add tags.</p>

				<div class="bg-gray-900 rounded-xl p-5 border border-gray-800 space-y-3">
					<div class="grid grid-cols-2 gap-3">
						<input bind:value={ruleName} placeholder="Rule name" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={rulePattern} placeholder="Match pattern (e.g. authentication failure)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<input bind:value={ruleSource} placeholder="Source filter (e.g. syslog)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
						<select bind:value={ruleSeverity} class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
							<option value="">Override severity...</option>
							<option value="critical">Critical</option>
							<option value="warning">Warning</option>
							<option value="info">Info</option>
						</select>
						<input bind:value={ruleTag} placeholder="Add tag (e.g. brute-force)" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
					</div>
					<button on:click={createRule} disabled={!ruleName || !rulePattern} class="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 rounded text-sm">Create Rule</button>
				</div>

				{#each rules as r}
					<div class="bg-gray-900 rounded-lg p-4 border border-gray-800">
						<div class="font-medium text-sm">{r.name}</div>
						<div class="text-xs text-gray-500 mt-0.5">
							Pattern: "{r.pattern}"{r.source_match ? ` | Source: ${r.source_match}` : ''}
							{r.set_severity ? ` | → ${r.set_severity}` : ''}{r.add_tag ? ` | +tag: ${r.add_tag}` : ''}
						</div>
					</div>
				{/each}
				{#if rules.length === 0}<div class="text-gray-600 text-sm">No rules defined yet.</div>{/if}
			</div>

		{:else if tab === 'audit'}
			<div class="max-w-4xl mx-auto">
				<h3 class="text-lg font-semibold mb-4">Audit Log</h3>
				<table class="w-full text-sm">
					<thead><tr class="text-gray-500 text-xs uppercase tracking-wider border-b border-gray-800">
						<th class="text-left py-2">Time</th><th class="text-left py-2">Action</th>
						<th class="text-left py-2">Detail</th><th class="text-left py-2">Source IP</th>
					</tr></thead>
					<tbody>
						{#each audit as a}
							<tr class="border-b border-gray-800/50">
								<td class="py-2 text-xs text-gray-500 font-mono">{a.created_at?.slice(0,19)}</td>
								<td class="py-2 font-medium">{a.action}</td>
								<td class="py-2 text-gray-400">{a.detail}</td>
								<td class="py-2 text-xs text-gray-500 font-mono">{a.remote_addr}</td>
							</tr>
						{/each}
					</tbody>
				</table>
				{#if audit.length === 0}<div class="text-gray-600 text-sm mt-4">No audit entries yet.</div>{/if}
			</div>

		{:else if tab === 'settings'}
			<div class="max-w-4xl mx-auto space-y-4">
				<h3 class="text-lg font-semibold mb-4">Configuration</h3>
				{#if settings}
					<div class="grid grid-cols-2 gap-4">
						<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
							<h4 class="text-sm font-semibold text-blue-400 mb-3">Scanner</h4>
							<div class="space-y-2 text-sm">
								<div class="flex justify-between"><span class="text-gray-500">Subnets</span><span class="font-mono text-xs">{settings.scanner?.subnets?.join(', ') || 'auto-detect'}</span></div>
								<div class="flex justify-between"><span class="text-gray-500">Interval</span><span>{settings.scanner?.interval}</span></div>
								<div class="flex justify-between"><span class="text-gray-500">Timeout</span><span>{settings.scanner?.timeout}</span></div>
							</div>
						</div>
						<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
							<h4 class="text-sm font-semibold text-blue-400 mb-3">Telemetry</h4>
							<div class="space-y-2 text-sm">
								<div class="flex justify-between"><span class="text-gray-500">SNMP</span><span class={settings.telemetry?.snmp_enabled ? 'text-emerald-400' : 'text-gray-600'}>{settings.telemetry?.snmp_enabled ? 'Active' : 'Disabled'}</span></div>
								<div class="flex justify-between"><span class="text-gray-500">Syslog</span><span class={settings.telemetry?.syslog_enabled ? 'text-emerald-400' : 'text-gray-600'}>{settings.telemetry?.syslog_enabled ? 'Active' : 'Disabled'}</span></div>
								<div class="flex justify-between"><span class="text-gray-500">HTTP Poller</span><span class={settings.telemetry?.poller_enabled ? 'text-emerald-400' : 'text-gray-600'}>{settings.telemetry?.poller_enabled ? 'Active' : 'Disabled'}</span></div>
							</div>
						</div>
						<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
							<h4 class="text-sm font-semibold text-blue-400 mb-3">Mesh</h4>
							<div class="space-y-2 text-sm">
								<div class="flex justify-between"><span class="text-gray-500">Status</span><span class={settings.mesh?.enabled ? 'text-emerald-400' : 'text-gray-600'}>{settings.mesh?.enabled ? 'Active' : 'Disabled'}</span></div>
								<div class="flex justify-between"><span class="text-gray-500">Node Type</span><span>{settings.mesh?.node_type}</span></div>
							</div>
						</div>
						<div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
							<h4 class="text-sm font-semibold text-blue-400 mb-3">AI</h4>
							<div class="space-y-2 text-sm">
								<div class="flex justify-between"><span class="text-gray-500">Status</span><span class={settings.ai?.enabled ? 'text-emerald-400' : 'text-gray-600'}>{settings.ai?.enabled ? 'Active' : 'Disabled'}</span></div>
							</div>
						</div>
					</div>
					<div class="flex gap-3 mt-4">
						<a href="/api/backup" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300">Download Backup</a>
						<a href="/api/docs/network" target="_blank" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300">Network Documentation</a>
						<a href="/api/devices?format=csv" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300">Export CSV</a>
						<a href="/topology.svg" target="_blank" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300">Export SVG Map</a>
					</div>
				{/if}
			</div>
		{/if}
	</div>
</div>
