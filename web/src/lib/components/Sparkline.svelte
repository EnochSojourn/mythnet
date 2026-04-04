<script>
	export let data = [];
	export let color = '#3b82f6';
	export let width = 60;
	export let height = 20;

	$: points = (() => {
		if (data.length < 2) return '';
		const max = Math.max(...data, 1);
		const min = Math.min(...data, 0);
		const range = max - min || 1;
		const step = width / (data.length - 1);
		return data.map((v, i) =>
			`${i * step},${height - ((v - min) / range) * (height - 2) - 1}`
		).join(' ');
	})();

	$: fillPoints = points
		? `0,${height} ${points} ${width},${height}`
		: '';
</script>

{#if data.length >= 2}
<svg {width} {height} class="inline-block">
	<polyline points={fillPoints} fill="{color}15" stroke="none" />
	<polyline points={points} fill="none" stroke={color} stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
</svg>
{/if}
