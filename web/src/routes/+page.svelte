<script>
	import { onMount, onDestroy } from 'svelte';
	import { devices, stats, scanning, selectedDeviceId } from '$lib/stores';
	import { getDevices, getStats, getHealth, triggerScan } from '$lib/api';
	import TopologyMap from '$lib/components/TopologyMap.svelte';
	import DeviceList from '$lib/components/DeviceList.svelte';
	import DeviceDetail from '$lib/components/DeviceDetail.svelte';
	import StatsBar from '$lib/components/StatsBar.svelte';
	import EventsFeed from '$lib/components/EventsFeed.svelte';
	import ChatPanel from '$lib/components/ChatPanel.svelte';
	import LoginPage from '$lib/components/LoginPage.svelte';
	import CommandPalette from '$lib/components/CommandPalette.svelte';
	import ToolsPanel from '$lib/components/ToolsPanel.svelte';
	import AdminPanel from '$lib/components/AdminPanel.svelte';

	let authenticated = !!localStorage.getItem('mythnet_creds');
	let paletteOpen = false;
	let toolsOpen = false;
	let adminOpen = false;
	let interval;
	let sidebarOpen = true;
	let sidebarTab = 'devices';
	let chatOpen = false;
	let ws;
	let wsConnected = false;

	function handleLogin() {
		authenticated = true;
		refresh();
		connectWS();
	}

	function logout() {
		localStorage.removeItem('mythnet_creds');
		authenticated = false;
		if (ws) ws.close();
		if (interval) clearInterval(interval);
	}

	async function refresh() {
		try {
			const [devData, statsData, health] = await Promise.all([
				getDevices(), getStats(), getHealth()
			]);
			devices.set(devData);
			stats.set(statsData);
			scanning.set(health.scanning);
		} catch (e) {
			// Backend may not be ready yet
		}
	}

	function connectWS() {
		const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
		ws = new WebSocket(`${proto}//${location.host}/api/ws`);
		ws.onopen = () => { wsConnected = true; };
		ws.onclose = () => {
			wsConnected = false;
			setTimeout(connectWS, 5000); // Reconnect
		};
		ws.onmessage = () => {
			// Any mutation → refresh all data
			refresh();
		};
	}

	async function handleScan() {
		try {
			await triggerScan();
			scanning.set(true);
		} catch {}
	}

	function globalKeydown(e) {
		if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
			e.preventDefault();
			paletteOpen = !paletteOpen;
		}
	}

	onMount(() => {
		if (authenticated) {
			refresh();
			connectWS();
		}
		interval = setInterval(() => { if (authenticated) refresh(); }, 15000);
		window.addEventListener('keydown', globalKeydown);
		return () => window.removeEventListener('keydown', globalKeydown);
	});

	onDestroy(() => {
		if (interval) clearInterval(interval);
		if (ws) ws.close();
	});
	</script>

{#if !authenticated}
	<LoginPage onLogin={handleLogin} />
{:else}
<div class="h-screen flex flex-col bg-gray-950 select-none">
	<!-- Top Bar -->
	<header class="flex items-center justify-between px-4 h-12 bg-gray-900/80 border-b border-gray-800/60 shrink-0 backdrop-blur-sm z-10">
		<div class="flex items-center gap-3">
			<button
				on:click={() => sidebarOpen = !sidebarOpen}
				class="text-gray-400 hover:text-white p-1 rounded transition-colors"
				title="Toggle sidebar"
			>
				<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
					<path d="M3 12h18M3 6h18M3 18h18"/>
				</svg>
			</button>
			<h1 class="text-base font-bold tracking-tight">
				<span class="text-blue-400">Myth</span><span class="text-gray-100">Net</span>
			</h1>
			<span class="text-[10px] text-gray-600 font-mono ml-1">v1.1</span>
			<button
				on:click={() => paletteOpen = true}
				class="ml-3 flex items-center gap-1.5 bg-gray-800/60 hover:bg-gray-800 border border-gray-700/40 rounded-md px-2.5 py-1 text-xs text-gray-500 transition-colors"
			>
				<svg viewBox="0 0 24 24" class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
				<span class="hidden sm:inline">Search</span>
				<kbd class="hidden sm:inline text-[9px] text-gray-600 bg-gray-900/60 px-1 py-0.5 rounded ml-1">⌘K</kbd>
			</button>
		</div>

		<div class="flex items-center gap-4">
			<!-- Admin panel -->
			<button
				on:click={() => adminOpen = true}
				class="px-3 py-1 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-md transition-colors"
			>Admin</button>

			<!-- Notification bell -->
			{#if $stats.critical_events > 0}
				<button
					on:click={() => { sidebarTab = 'events'; sidebarOpen = true; }}
					class="relative p-1 text-red-400 hover:text-red-300 transition-colors"
					title="{$stats.critical_events} critical/warning events"
				>
					<svg viewBox="0 0 24 24" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0"/>
					</svg>
					<span class="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 rounded-full text-[9px] font-bold flex items-center justify-center text-white">
						{$stats.critical_events > 9 ? '9+' : $stats.critical_events}
					</span>
				</button>
			{/if}
			{#if $scanning}
				<div class="flex items-center gap-2 text-xs text-amber-400">
					<span class="relative flex h-2 w-2">
						<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
						<span class="relative inline-flex rounded-full h-2 w-2 bg-amber-400"></span>
					</span>
					Scanning
				</div>
			{:else}
				<div class="flex items-center gap-2 text-xs text-gray-500">
					<span class="w-2 h-2 rounded-full bg-emerald-500/60"></span>
					Idle
				</div>
			{/if}
			<button
				on:click={() => { toolsOpen = !toolsOpen; chatOpen = false; }}
				class="px-3 py-1 text-xs font-medium rounded-md transition-colors {toolsOpen ? 'bg-cyan-600 hover:bg-cyan-500 text-cyan-100' : 'bg-gray-800 hover:bg-gray-700 text-gray-300'}"
			>Tools</button>
			<button
				on:click={() => { chatOpen = !chatOpen; toolsOpen = false; }}
				class="px-3 py-1 text-xs font-medium rounded-md transition-colors"
				class:bg-violet-600={chatOpen}
				class:hover:bg-violet-500={chatOpen}
				class:bg-gray-800={!chatOpen}
				class:hover:bg-gray-700={!chatOpen}
				class:text-violet-100={chatOpen}
				class:text-gray-300={!chatOpen}
			>
				AI Chat
			</button>
			<button
				on:click={handleScan}
				disabled={$scanning}
				class="px-3 py-1 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 rounded-md transition-colors"
			>
				Scan Now
			</button>
			<button
				on:click={logout}
				class="px-2 py-1 text-xs text-gray-500 hover:text-gray-300 transition-colors"
				title="Sign out"
			>
				<svg viewBox="0 0 24 24" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>
				</svg>
			</button>
		</div>
	</header>

	<!-- Main Content -->
	<div class="flex flex-1 overflow-hidden">
		<!-- Sidebar -->
		{#if sidebarOpen}
			<aside class="w-72 max-md:absolute max-md:inset-y-12 max-md:left-0 max-md:z-30 max-md:shadow-2xl flex flex-col bg-gray-900/95 md:bg-gray-900/40 border-r border-gray-800/60 shrink-0 z-10">
				<StatsBar />
				<div class="flex border-y border-gray-800/40 bg-gray-900/30">
					<button
						class="flex-1 px-3 py-2 text-[10px] font-semibold uppercase tracking-widest transition-colors"
						class:text-blue-400={sidebarTab === 'devices'}
						class:text-gray-500={sidebarTab !== 'devices'}
						on:click={() => sidebarTab = 'devices'}
					>
						Devices ({$devices.length})
					</button>
					<button
						class="flex-1 px-3 py-2 text-[10px] font-semibold uppercase tracking-widest transition-colors"
						class:text-blue-400={sidebarTab === 'events'}
						class:text-gray-500={sidebarTab !== 'events'}
						on:click={() => sidebarTab = 'events'}
					>
						Events
					</button>
				</div>
				<div class="flex-1 overflow-y-auto">
					{#if sidebarTab === 'devices'}
						<DeviceList />
					{:else}
						<EventsFeed />
					{/if}
				</div>
			</aside>
		{/if}

		<!-- Topology Map -->
		<main class="flex-1 relative overflow-hidden">
			<TopologyMap />

			<!-- Legend overlay -->
			<div class="absolute bottom-4 left-4 bg-gray-900/80 backdrop-blur-sm rounded-lg border border-gray-800/40 px-3 py-2 text-[10px] text-gray-500 pointer-events-none">
				<div class="flex flex-wrap gap-x-3 gap-y-1">
					{#each Object.entries({ 'Network': '#3b82f6', 'Server': '#22c55e', 'Endpoint': '#64748b', 'IoT': '#a855f7', 'Camera': '#ef4444', 'Firewall': '#f97316' }) as [label, color]}
						<div class="flex items-center gap-1">
							<span class="w-2 h-2 rounded-full" style="background:{color}"></span>
							{label}
						</div>
					{/each}
				</div>
			</div>
		</main>

		<!-- Right Panel: Device Detail or Chat -->
		{#if toolsOpen}
			<aside class="w-96 max-md:absolute max-md:inset-y-12 max-md:right-0 max-md:z-30 max-md:shadow-2xl shrink-0 z-10">
				<ToolsPanel onClose={() => toolsOpen = false} />
			</aside>
		{:else if chatOpen}
			<aside class="w-96 max-md:absolute max-md:inset-y-12 max-md:right-0 max-md:z-30 max-md:shadow-2xl shrink-0 z-10">
				<ChatPanel onClose={() => chatOpen = false} />
			</aside>
		{:else if $selectedDeviceId}
			<aside class="w-80 max-md:absolute max-md:inset-y-12 max-md:right-0 max-md:z-30 max-md:shadow-2xl shrink-0 z-10">
				<DeviceDetail />
			</aside>
		{/if}
	</div>
</div>

{#if paletteOpen}
	<CommandPalette onClose={() => paletteOpen = false} />
{/if}

{#if adminOpen}
	<AdminPanel onClose={() => adminOpen = false} />
{/if}
{/if}
