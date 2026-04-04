<script>
	import { onMount, onDestroy } from 'svelte';
	import * as d3 from 'd3';
	import { devices, selectedDeviceId } from '$lib/stores';

	let container;
	let svgEl;
	let sim;
	let prevIds = '';
	let currentDevices = [];
	let flowData = [];

	// Fetch persistent traffic graph (who has talked to whom, ever)
	async function fetchFlows() {
		try {
			const res = await fetch('/api/traffic');
			if (res.ok) {
				const traffic = await res.json();
				// Convert traffic graph to flow format, only between known devices
				flowData = traffic.map(t => ({ src_ip: t.src, dst_ip: t.dst, port: t.port, connections: t.connections }));
			}
		} catch {}
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

	const TYPE_ABBR = {
		'Network Equipment': 'NET',
		'Server': 'SRV',
		'Endpoint': 'EP',
		'IoT': 'IoT',
		'IP Camera': 'CAM',
		'AV Equipment': 'AV',
		'Firewall': 'FW',
		'NAS': 'NAS',
		'Printer': 'PRT',
		'Virtual Machine': 'VM',
		'Media Player': 'MP',
		'SBC': 'SBC'
	};

	// SVG path icons (16x16 viewbox, centered at 0,0 → translate -8,-8)
	const TYPE_ICONS = {
		'Network Equipment': 'M1 4h14v2H1zM3 8h10v2H3zM5 12h6v2H5z', // switch/stack
		'Server':            'M2 1h12v4H2zm0 5h12v4H2zm0 5h12v4H2zM4 3h1v1H4zm0 5h1v1H4zm0 5h1v1H4z',
		'Endpoint':          'M2 2h12v9H2zm3 10h6v2H5zM3 14h10v1H3z', // monitor
		'IoT':               'M8 1a7 7 0 110 14A7 7 0 018 1zm0 3a4 4 0 100 8 4 4 0 000-8zm0 2a2 2 0 110 4 2 2 0 010-4z',
		'IP Camera':         'M1 4h10v8H1zm11 1l4 2v4l-4 2z', // camera
		'Firewall':          'M8 1L1 5v6l7 4 7-4V5z', // shield
		'NAS':               'M2 2h12v3H2zm0 4h12v3H2zm0 4h12v3H2zM12 3h1v1h-1zm0 4h1v1h-1zm0 4h1v1h-1z',
		'Printer':           'M4 1h8v4H4zM2 6h12v6H2zM4 13h8v2H4z',
		'Virtual Machine':   'M1 3h14v10H1zM4 6h3v2H4zM9 6h3v2H9zM4 9h8v2H4z', // vm grid
		'Media Player':      'M3 2h10v12H3zM6 7l5 3-5 3z', // play
		'SBC':               'M1 3h14v10H1zM3 6h2v1H3zM3 8h2v1H3zM7 5h6v6H7z', // board
		'subnet':            'M4 8a4 4 0 118 0 4 4 0 01-8 0zM8 1v3M8 12v3M1 8h3M12 8h3',
	};

	function col(type) {
		return TYPE_COLORS[type] || '#64748b';
	}

	// Human-readable device label for the topology map
	const VENDOR_LABELS = {
		'eero': 'eero',
		'Ring': 'Ring',
		'Peloton': 'Peloton',
		'Sony': 'PlayStation',
		'Tuya': 'Tuya',
		'AMPAK': 'Smart TV',
		'Texas Instruments': 'Smart Hub',
		'Gaoshengda': 'IoT Device',
		'Apple': 'Apple',
		'Randomized MAC': 'Phone/Tablet',
		'Sonos': 'Sonos',
		'Roku': 'Roku',
		'Google': 'Google',
		'Amazon': 'Amazon',
		'Philips Hue': 'Hue Bridge',
		'Raspberry Pi': 'Raspberry Pi',
		'Synology': 'Synology NAS',
	};

	function bestName(dev) {
		// Prefer hostname
		if (dev.hostname && dev.hostname !== '_gateway') return dev.hostname;
		if (dev.hostname === '_gateway') return 'Gateway';
		// Friendly vendor label
		if (dev.vendor && VENDOR_LABELS[dev.vendor]) return VENDOR_LABELS[dev.vendor];
		// Raw vendor
		if (dev.vendor) return dev.vendor;
		// Last resort: last octet
		const parts = dev.ip.split('.');
		return '.' + parts[3];
	}

	function buildGraph(list) {
		const nodes = [];
		const links = [];
		const subnets = new Map();

		for (const dev of list) {
			const p = dev.ip.split('.');
			const key = `${p[0]}.${p[1]}.${p[2]}.0/24`;
			if (!subnets.has(key)) {
				subnets.set(key, { id: `sub:${key}`, label: key, nodeType: 'subnet', radius: 30 });
			}
		}

		for (const s of subnets.values()) nodes.push(s);

		for (const dev of list) {
			const p = dev.ip.split('.');
			const key = `${p[0]}.${p[1]}.${p[2]}.0/24`;
			const pc = (dev.ports || []).length;
			nodes.push({
				id: dev.id,
				label: bestName(dev),
				ip: dev.ip,
				mac: dev.mac || '',
				vendor: dev.vendor || '',
				os: dev.os_guess || '',
				deviceType: dev.device_type || 'Endpoint',
				online: dev.is_online,
				nodeType: 'device',
				radius: Math.max(10, Math.min(22, 10 + pc * 3))
			});
			links.push({ source: `sub:${key}`, target: dev.id });
		}

		return { nodes, links };
	}

	function fullRender(list) {
		if (!container || list.length === 0) return;

		const rect = container.getBoundingClientRect();
		const w = rect.width;
		const h = rect.height;
		if (w === 0 || h === 0) return;

		// Save positions from previous simulation
		const saved = {};
		if (sim) {
			sim.nodes().forEach(n => { saved[n.id] = { x: n.x, y: n.y }; });
			sim.stop();
		}

		// Clear
		d3.select(container).selectAll('svg').remove();
		d3.select(container).selectAll('.tt').remove();

		const { nodes, links } = buildGraph(list);

		// Restore positions
		for (const n of nodes) {
			if (saved[n.id]) { n.x = saved[n.id].x; n.y = saved[n.id].y; }
		}

		const svg = d3.select(container).append('svg')
			.attr('width', w).attr('height', h);
		svgEl = svg;

		// Glow filter
		const defs = svg.append('defs');
		const f = defs.append('filter').attr('id', 'glow');
		f.append('feGaussianBlur').attr('stdDeviation', '3.5').attr('result', 'b');
		const merge = f.append('feMerge');
		merge.append('feMergeNode').attr('in', 'b');
		merge.append('feMergeNode').attr('in', 'SourceGraphic');

		// Grid pattern background
		const pattern = defs.append('pattern')
			.attr('id', 'grid').attr('width', 40).attr('height', 40)
			.attr('patternUnits', 'userSpaceOnUse');
		pattern.append('path')
			.attr('d', 'M 40 0 L 0 0 0 40')
			.attr('fill', 'none').attr('stroke', '#0f172a').attr('stroke-width', 0.5);
		svg.append('rect').attr('width', '100%').attr('height', '100%').attr('fill', 'url(#grid)');

		const g = svg.append('g');

		// Zoom
		svg.call(d3.zoom()
			.scaleExtent([0.1, 6])
			.on('zoom', e => g.attr('transform', e.transform))
		);

		// Simulation
		sim = d3.forceSimulation(nodes)
			.force('charge', d3.forceManyBody().strength(d => d.nodeType === 'subnet' ? -600 : -200))
			.force('link', d3.forceLink(links).id(d => d.id).distance(140).strength(0.6))
			.force('center', d3.forceCenter(w / 2, h / 2))
			.force('collision', d3.forceCollide().radius(d => d.radius + 14))
			.force('x', d3.forceX(w / 2).strength(0.03))
			.force('y', d3.forceY(h / 2).strength(0.03))
			.alphaDecay(0.025);

		// Links
		// Animated link dashes
		const linkDefs = defs.append('style').text(`
			@keyframes dash { to { stroke-dashoffset: -20; } }
			.link-active { animation: dash 2s linear infinite; }
			@keyframes breathe { 0%,100% { stroke-opacity: 0.15; } 50% { stroke-opacity: 0.35; } }
			.glow-ring { animation: breathe 3s ease-in-out infinite; }
		`);

		const link = g.append('g').attr('class', 'links')
			.selectAll('line').data(links).join('line')
			.attr('stroke', '#1e293b').attr('stroke-width', 1.5).attr('stroke-opacity', 0.4)
			.attr('stroke-dasharray', '4 4').attr('class', 'link-active');

		// Nodes
		const node = g.append('g').attr('class', 'nodes')
			.selectAll('g').data(nodes).join('g')
			.attr('class', d => d.nodeType === 'device' ? 'device-node' : 'subnet-node')
			.attr('cursor', d => d.nodeType === 'device' ? 'pointer' : 'grab')
			.call(d3.drag()
				.on('start', (e, d) => {
					if (!e.active) sim.alphaTarget(0.3).restart();
					d.fx = d.x; d.fy = d.y;
				})
				.on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
				.on('end', (e, d) => {
					if (!e.active) sim.alphaTarget(0);
					d.fx = null; d.fy = null;
				})
			);

		// Outer glow ring with breathing animation
		node.filter(d => d.nodeType === 'device' && d.online)
			.append('circle')
			.attr('class', 'glow-ring')
			.attr('r', d => d.radius + 5)
			.attr('fill', 'none')
			.attr('stroke', d => col(d.deviceType))
			.attr('stroke-width', 1.5)
			.attr('stroke-opacity', 0.2)
			.attr('filter', 'url(#glow)');

		// Main circle
		node.append('circle')
			.attr('class', 'main-circle')
			.attr('r', d => d.radius)
			.attr('fill', d => d.nodeType === 'subnet' ? '#0f172a' : col(d.deviceType))
			.attr('stroke', d => d.nodeType === 'subnet' ? '#334155' : (d.online ? col(d.deviceType) : '#7f1d1d'))
			.attr('stroke-width', 2)
			.attr('fill-opacity', d => d.nodeType === 'subnet' ? 1 : (d.online ? 0.85 : 0.25))
			.attr('stroke-opacity', d => d.online !== false ? 0.9 : 0.35);

		// Inner icon (SVG path) or fallback text
		node.each(function(d) {
			const el = d3.select(this);
			const iconKey = d.nodeType === 'subnet' ? 'subnet' : d.deviceType;
			const iconPath = TYPE_ICONS[iconKey];
			if (iconPath && d.radius >= 10) {
				const scale = (d.radius * 1.1) / 16;
				el.append('path')
					.attr('d', iconPath)
					.attr('transform', `translate(${-8 * scale},${-8 * scale}) scale(${scale})`)
					.attr('fill', d.nodeType === 'subnet' ? '#475569' : 'rgba(255,255,255,0.85)')
					.attr('pointer-events', 'none');
			} else {
				el.append('text')
					.attr('text-anchor', 'middle').attr('dy', '0.35em')
					.attr('fill', d.nodeType === 'subnet' ? '#475569' : 'rgba(255,255,255,0.9)')
					.attr('font-size', '8px').attr('font-weight', '700')
					.attr('pointer-events', 'none')
					.text(TYPE_ABBR[d.deviceType] || 'EP');
			}
		});

		// Label below
		node.append('text')
			.attr('dy', d => d.radius + 14)
			.attr('text-anchor', 'middle')
			.attr('fill', '#6b7280')
			.attr('font-size', '10px')
			.attr('pointer-events', 'none')
			.text(d => {
				const l = d.label;
				return l.length > 18 ? l.slice(0, 16) + '…' : l;
			});

		// Tooltip
		const tt = d3.select(container).append('div')
			.attr('class', 'tt')
			.style('position', 'absolute')
			.style('background', 'rgba(15,23,42,0.95)')
			.style('border', '1px solid #1e293b')
			.style('border-radius', '10px')
			.style('padding', '12px 16px')
			.style('font-size', '12px')
			.style('color', '#e2e8f0')
			.style('pointer-events', 'none')
			.style('opacity', 0)
			.style('z-index', '50')
			.style('max-width', '260px')
			.style('backdrop-filter', 'blur(8px)')
			.style('box-shadow', '0 12px 32px rgba(0,0,0,0.6)')
			.style('transition', 'opacity 0.12s ease');

		node.on('mouseenter', (event, d) => {
			if (d.nodeType === 'subnet') return;
			let html = `<div style="font-weight:600;color:${col(d.deviceType)};margin-bottom:6px">${d.label}</div>`;
			html += `<div style="font-family:monospace;color:#94a3b8;font-size:11px">${d.ip}</div>`;
			if (d.mac) html += `<div style="font-family:monospace;color:#64748b;font-size:10px;margin-top:2px">${d.mac}</div>`;
			if (d.vendor) html += `<div style="color:#94a3b8;margin-top:4px">${d.vendor}</div>`;
			if (d.os) html += `<div style="color:#94a3b8">${d.os}</div>`;
			html += `<div style="margin-top:6px;font-size:11px;display:flex;justify-content:space-between">`;
			html += `<span style="color:${d.online ? '#4ade80' : '#f87171'}">${d.online ? '● Online' : '● Offline'}</span>`;
			html += `<span style="color:#64748b">${d.deviceType}</span></div>`;
			tt.html(html).style('opacity', 1);
		})
		.on('mousemove', event => {
			const [mx, my] = d3.pointer(event, container);
			tt.style('left', (mx + 16) + 'px').style('top', (my - 12) + 'px');
		})
		.on('mouseleave', () => tt.style('opacity', 0));

		// Click to select
		node.on('click', (event, d) => {
			if (d.nodeType === 'device') {
				event.stopPropagation();
				selectedDeviceId.update(cur => cur === d.id ? null : d.id);
			}
		});

		// Click background to deselect
		svg.on('click', () => selectedDeviceId.set(null));

		// Highlight selected node
		const unsubSel = selectedDeviceId.subscribe(id => {
			node.select('.main-circle')
				.attr('stroke-width', d => d.id === id ? 3 : 2)
				.attr('stroke', d => {
					if (d.id === id) return '#ffffff';
					if (d.nodeType === 'subnet') return '#334155';
					return d.online ? col(d.deviceType) : '#7f1d1d';
				});
		});

		// Flow overlay layer
		const flowLayer = g.append('g').attr('class', 'flow-layer');

		function updateFlows() {
			fetchFlows().then(() => {
				flowLayer.selectAll('line').remove();
				const nodeMap = {};
				sim.nodes().forEach(n => { if (n.nodeType === 'device') nodeMap[n.ip] = n; });

				for (const f of flowData) {
					const src = nodeMap[f.src_ip];
					const dst = nodeMap[f.dst_ip];
					if (src && dst && src.id !== dst.id) {
						const conns = f.connections || 1;
						const width = Math.max(1, Math.min(4, Math.log2(conns + 1)));
						const opacity = Math.max(0.3, Math.min(0.8, conns / 50));
						flowLayer.append('line')
							.attr('x1', src.x).attr('y1', src.y)
							.attr('x2', dst.x).attr('y2', dst.y)
							.attr('stroke', '#22d3ee')
							.attr('stroke-width', width)
							.attr('stroke-opacity', opacity)
							.attr('stroke-dasharray', '3 3')
							.attr('class', 'link-active');
					}
				}
			});
		}

		// Initial flow fetch + periodic refresh
		setTimeout(updateFlows, 2000);
		const flowInterval = setInterval(updateFlows, 10000);
		container.__flowInterval = flowInterval;

		// Tick
		sim.on('tick', () => {
			link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
				.attr('x2', d => d.target.x).attr('y2', d => d.target.y);
			node.attr('transform', d => `translate(${d.x},${d.y})`);
		});

		// Store unsub for cleanup
		container.__unsubSel = unsubSel;
	}

	function updateVisuals(list) {
		if (!svgEl) return;
		const map = new Map(list.map(d => [d.id, d]));
		svgEl.selectAll('.device-node').each(function(d) {
			const dev = map.get(d.id);
			if (!dev) return;
			d.online = dev.is_online;
			const el = d3.select(this);
			el.select('.main-circle')
				.attr('fill-opacity', d.online ? 0.85 : 0.25)
				.attr('stroke-opacity', d.online ? 0.9 : 0.35);
		});
	}

	function handleData(list) {
		currentDevices = list;
		if (list.length === 0) return;
		const ids = list.map(d => d.id).sort().join(',');
		if (ids === prevIds) {
			updateVisuals(list);
		} else {
			prevIds = ids;
			fullRender(list);
		}
	}

	const unsub = devices.subscribe(handleData);

	onMount(() => {
		fullRender(currentDevices);

		const ro = new ResizeObserver(() => {
			prevIds = '';
			fullRender(currentDevices);
		});
		ro.observe(container);

		return () => {
			ro.disconnect();
			if (container?.__unsubSel) container.__unsubSel();
			if (container?.__flowInterval) clearInterval(container.__flowInterval);
		};
	});

	onDestroy(() => {
		unsub();
		if (sim) sim.stop();
	});
</script>

<div bind:this={container} class="w-full h-full relative overflow-hidden" style="background:#060a14">
	{#if currentDevices.length === 0}
		<div class="absolute inset-0 flex items-center justify-center pointer-events-none">
			<div class="text-center">
				<svg class="w-16 h-16 mx-auto mb-4 text-gray-800" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1">
					<path d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
				</svg>
				<div class="text-gray-600 text-base font-medium mb-1">Scanning network...</div>
				<div class="text-gray-700 text-sm">Devices will appear here as they're discovered</div>
			</div>
		</div>
	{/if}
</div>
