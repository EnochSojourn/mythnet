<script>
	import { onMount, onDestroy } from 'svelte';
	import { devices, selectedDeviceId, scanning } from '$lib/stores';
	import { triggerScan } from '$lib/api';

	export let onClose;

	let query = '';
	let selectedIdx = 0;
	let inputEl;

	const ACTIONS = [
		{ id: 'scan', label: 'Trigger Network Scan', icon: '~', category: 'Actions' },
		{ id: 'export', label: 'Export Devices as CSV', icon: '↓', category: 'Actions' },
		{ id: 'report', label: 'Generate AI Report', icon: '✦', category: 'Actions' },
	];

	$: results = buildResults(query, $devices);

	function buildResults(q, devs) {
		const items = [];
		const lower = q.toLowerCase();

		// Matching devices
		const matchedDevs = q
			? devs.filter(d =>
				(d.ip || '').toLowerCase().includes(lower) ||
				(d.hostname || '').toLowerCase().includes(lower) ||
				(d.vendor || '').toLowerCase().includes(lower) ||
				(d.mac || '').toLowerCase().includes(lower) ||
				(d.device_type || '').toLowerCase().includes(lower)
			)
			: devs.slice(0, 8);

		for (const d of matchedDevs.slice(0, 10)) {
			items.push({
				id: 'device:' + d.id,
				label: d.hostname || d.ip,
				detail: `${d.ip}${d.vendor ? ' · ' + d.vendor : ''}`,
				icon: d.is_online ? '●' : '○',
				iconColor: d.is_online ? '#4ade80' : '#f87171',
				category: 'Devices',
			});
		}

		// Matching actions
		const matchedActions = q
			? ACTIONS.filter(a => a.label.toLowerCase().includes(lower))
			: ACTIONS;

		for (const a of matchedActions) {
			items.push(a);
		}

		return items;
	}

	function handleKeydown(e) {
		if (e.key === 'Escape') {
			onClose();
		} else if (e.key === 'ArrowDown') {
			e.preventDefault();
			selectedIdx = Math.min(selectedIdx + 1, results.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			selectedIdx = Math.max(selectedIdx - 1, 0);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (results[selectedIdx]) execute(results[selectedIdx]);
		}
	}

	function execute(item) {
		if (item.id.startsWith('device:')) {
			selectedDeviceId.set(item.id.replace('device:', ''));
			onClose();
		} else if (item.id === 'scan') {
			triggerScan();
			scanning.set(true);
			onClose();
		} else if (item.id === 'export') {
			window.open('/api/devices?format=csv', '_blank');
			onClose();
		} else if (item.id === 'report') {
			fetch('/api/reports', { method: 'POST', headers: authHeaders() });
			onClose();
		}
	}

	function authHeaders() {
		const creds = localStorage.getItem('mythnet_creds');
		return creds ? { 'Authorization': 'Basic ' + creds } : {};
	}

	$: selectedIdx = Math.min(selectedIdx, Math.max(results.length - 1, 0));

	onMount(() => {
		if (inputEl) inputEl.focus();
	});

	// Global keyboard shortcut
	let globalHandler;
	onMount(() => {
		globalHandler = (e) => {
			if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
				e.preventDefault();
				if (inputEl) inputEl.focus();
			}
		};
		window.addEventListener('keydown', globalHandler);
		return () => window.removeEventListener('keydown', globalHandler);
	});
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
<div class="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]" on:click|self={onClose}>
	<div class="absolute inset-0 bg-black/60 backdrop-blur-sm" on:click={onClose}></div>

	<div class="relative w-full max-w-lg mx-4 bg-gray-900 border border-gray-700/50 rounded-xl shadow-2xl overflow-hidden">
		<!-- Search input -->
		<div class="flex items-center gap-3 px-4 py-3 border-b border-gray-800">
			<svg viewBox="0 0 24 24" class="w-5 h-5 text-gray-500 shrink-0" fill="none" stroke="currentColor" stroke-width="2">
				<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
			</svg>
			<input
				bind:this={inputEl}
				bind:value={query}
				on:keydown={handleKeydown}
				placeholder="Search devices, run actions..."
				class="flex-1 bg-transparent text-sm focus:outline-none placeholder:text-gray-600"
			/>
			<kbd class="text-[10px] text-gray-600 bg-gray-800 px-1.5 py-0.5 rounded">ESC</kbd>
		</div>

		<!-- Results -->
		<div class="max-h-[50vh] overflow-y-auto py-1">
			{#each results as item, i}
				{#if i === 0 || results[i-1]?.category !== item.category}
					<div class="px-4 pt-2 pb-1 text-[10px] text-gray-600 uppercase tracking-wider">{item.category}</div>
				{/if}
				<button
					class="w-full flex items-center gap-3 px-4 py-2 text-left text-sm transition-colors {i === selectedIdx ? 'bg-blue-600 bg-opacity-20' : ''}"
					on:click={() => execute(item)}
					on:mouseenter={() => selectedIdx = i}
				>
					<span class="w-5 text-center text-xs shrink-0" style:color={item.iconColor || '#6b7280'}>
						{item.icon || '→'}
					</span>
					<div class="flex-1 min-w-0">
						<div class="truncate">{item.label}</div>
						{#if item.detail}
							<div class="text-xs text-gray-500 truncate">{item.detail}</div>
						{/if}
					</div>
				</button>
			{/each}
			{#if results.length === 0}
				<div class="px-4 py-6 text-center text-gray-600 text-sm">No results</div>
			{/if}
		</div>
	</div>
</div>
