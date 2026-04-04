<script>
	export let onLogin;

	let password = '';
	let error = '';
	let loading = false;

	async function submit() {
		if (!password.trim()) return;
		loading = true;
		error = '';

		try {
			const creds = btoa('admin:' + password);
			const res = await fetch('/api/stats', {
				headers: { 'Authorization': 'Basic ' + creds }
			});

			if (res.ok) {
				localStorage.setItem('mythnet_creds', creds);
				onLogin();
			} else {
				error = 'Invalid password';
			}
		} catch {
			error = 'Cannot reach server';
		}

		loading = false;
	}

	function handleKey(e) {
		if (e.key === 'Enter') submit();
	}
</script>

<div class="h-screen flex items-center justify-center bg-gray-950">
	<div class="w-full max-w-sm mx-4">
		<div class="text-center mb-8">
			<h1 class="text-3xl font-bold tracking-tight mb-2">
				<span class="text-blue-400">Myth</span><span class="text-gray-100">Net</span>
			</h1>
			<p class="text-sm text-gray-500">Network Monitoring & Threat Detection</p>
		</div>

		<div class="bg-gray-900/60 border border-gray-800/60 rounded-xl p-6 backdrop-blur-sm">
			<label class="block text-[11px] text-gray-500 uppercase tracking-wider mb-2" for="password">
				Admin Password
			</label>
			<input
				id="password"
				type="password"
				bind:value={password}
				on:keydown={handleKey}
				placeholder="Enter password"
				autofocus
				class="w-full bg-gray-800/60 border border-gray-700/50 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500/50 placeholder:text-gray-600 mb-4"
			/>

			{#if error}
				<div class="text-red-400 text-xs mb-3">{error}</div>
			{/if}

			<button
				on:click={submit}
				disabled={loading || !password.trim()}
				class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 rounded-lg text-sm font-medium transition-colors"
			>
				{loading ? 'Authenticating...' : 'Sign In'}
			</button>
		</div>

		<p class="text-center text-[11px] text-gray-700 mt-6">
			Password is in <code class="text-gray-600">mythnet-data/password</code>
		</p>
	</div>
</div>
