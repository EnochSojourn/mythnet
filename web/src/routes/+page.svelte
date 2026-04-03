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

	let interval;
	let sidebarOpen = true;
	let sidebarTab = 'devices';
	let chatOpen = false;

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

	async function handleScan() {
		try {
			await triggerScan();
			scanning.set(true);
		} catch {}
	}

	onMount(() => {
		refresh();
		interval = setInterval(refresh, 5000);
	});

	onDestroy(() => {
		if (interval) clearInterval(interval);
	});
</script>

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
			<span class="text-[10px] text-gray-600 font-mono ml-1">v0.3</span>
		</div>

		<div class="flex items-center gap-4">
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
				on:click={() => chatOpen = !chatOpen}
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
		</div>
	</header>

	<!-- Main Content -->
	<div class="flex flex-1 overflow-hidden">
		<!-- Sidebar -->
		{#if sidebarOpen}
			<aside class="w-72 flex flex-col bg-gray-900/40 border-r border-gray-800/60 shrink-0 z-10">
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
		{#if chatOpen}
			<aside class="w-96 shrink-0 z-10">
				<ChatPanel onClose={() => chatOpen = false} />
			</aside>
		{:else if $selectedDeviceId}
			<aside class="w-80 shrink-0 z-10">
				<DeviceDetail />
			</aside>
		{/if}
	</div>
</div>
