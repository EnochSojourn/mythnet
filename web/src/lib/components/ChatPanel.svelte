<script>
	import { onMount, onDestroy } from 'svelte';

	let messages = [];
	let input = '';
	let ws = null;
	let streaming = false;
	let messagesEl;
	let connected = false;

	function connect() {
		const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
		ws = new WebSocket(`${proto}//${location.host}/api/chat`);

		ws.onopen = () => { connected = true; };
		ws.onclose = () => { connected = false; };
		ws.onerror = () => { connected = false; };

		ws.onmessage = (event) => {
			const data = JSON.parse(event.data);

			if (data.type === 'chunk') {
				const last = messages[messages.length - 1];
				if (last && last.role === 'assistant') {
					last.content += data.content;
					messages = messages;
				} else {
					messages = [...messages, { role: 'assistant', content: data.content }];
				}
				scrollBottom();
			} else if (data.type === 'error') {
				messages = [...messages, { role: 'error', content: data.content }];
				streaming = false;
			} else if (data.type === 'done') {
				streaming = false;
			}
		};
	}

	function send() {
		if (!input.trim() || streaming || !connected) return;
		messages = [...messages, { role: 'user', content: input }];
		ws.send(JSON.stringify({ content: input }));
		input = '';
		streaming = true;
		scrollBottom();
	}

	function handleKeydown(e) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	}

	function scrollBottom() {
		setTimeout(() => {
			if (messagesEl) messagesEl.scrollTop = messagesEl.scrollHeight;
		}, 10);
	}

	function renderMd(text) {
		return text
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
			.replace(/```([\s\S]*?)```/g, '<pre class="bg-gray-800/80 rounded p-2 my-1 text-xs overflow-x-auto">$1</pre>')
			.replace(/`([^`]+)`/g, '<code class="bg-gray-800/80 px-1 rounded text-xs">$1</code>')
			.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
			.replace(/^### (.+)$/gm, '<div class="font-semibold mt-2 text-sm">$1</div>')
			.replace(/^## (.+)$/gm, '<div class="font-semibold mt-3 text-sm text-blue-300">$1</div>')
			.replace(/^- (.+)$/gm, '<div class="ml-3">• $1</div>')
			.replace(/\n/g, '<br>');
	}

	export let onClose;

	onMount(() => connect());
	onDestroy(() => { if (ws) ws.close(); });
</script>

<div class="h-full flex flex-col bg-gray-900 border-l border-gray-800">
	<!-- Header -->
	<div class="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 shrink-0">
		<div class="flex items-center gap-2">
			<span class="text-sm font-semibold">MythNet AI</span>
			{#if connected}
				<span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
			{:else}
				<span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>
			{/if}
		</div>
		{#if onClose}
			<button on:click={onClose} class="text-gray-500 hover:text-gray-300 text-lg leading-none">&times;</button>
		{/if}
	</div>

	<!-- Messages -->
	<div bind:this={messagesEl} class="flex-1 overflow-y-auto p-3 space-y-3">
		{#if messages.length === 0}
			<div class="text-center text-gray-600 text-xs mt-8 space-y-2">
				<div class="text-2xl mb-3">🔍</div>
				<div class="font-medium text-gray-400">Ask about your network</div>
				<div>"What devices are online?"</div>
				<div>"Any security concerns?"</div>
				<div>"Summarize recent events"</div>
			</div>
		{/if}

		{#each messages as msg}
			{#if msg.role === 'user'}
				<div class="flex justify-end">
					<div class="bg-blue-600/30 border border-blue-500/20 rounded-lg px-3 py-2 text-sm max-w-[85%]">
						{msg.content}
					</div>
				</div>
			{:else if msg.role === 'error'}
				<div class="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-xs text-red-400">
					{msg.content}
				</div>
			{:else}
				<div class="bg-gray-800/40 rounded-lg px-3 py-2 text-sm leading-relaxed max-w-[95%]">
					{@html renderMd(msg.content)}
				</div>
			{/if}
		{/each}

		{#if streaming}
			<div class="flex items-center gap-1 text-gray-500 text-xs px-1">
				<span class="animate-pulse">●</span> Thinking...
			</div>
		{/if}
	</div>

	<!-- Input -->
	<div class="border-t border-gray-800 p-3 shrink-0">
		<div class="flex gap-2">
			<input
				bind:value={input}
				on:keydown={handleKeydown}
				placeholder={connected ? "Ask about your network..." : "Connecting..."}
				disabled={!connected}
				class="flex-1 bg-gray-800/60 border border-gray-700/50 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500/50 disabled:opacity-50 placeholder:text-gray-600"
			/>
			<button
				on:click={send}
				disabled={streaming || !connected || !input.trim()}
				class="px-3 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 rounded-lg text-sm transition-colors shrink-0"
			>
				Send
			</button>
		</div>
	</div>
</div>
