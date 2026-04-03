const BASE = '';

async function fetchJSON(path) {
	const res = await fetch(`${BASE}${path}`);
	if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
	return res.json();
}

export function getHealth() {
	return fetchJSON('/api/health');
}

export function getStats() {
	return fetchJSON('/api/stats');
}

export function getDevices() {
	return fetchJSON('/api/devices');
}

export function getDevice(id) {
	return fetchJSON(`/api/devices/${id}`);
}

export function getScans() {
	return fetchJSON('/api/scans');
}

export function getEvents(opts = {}) {
	const params = new URLSearchParams();
	if (opts.limit) params.set('limit', opts.limit);
	if (opts.device_id) params.set('device_id', opts.device_id);
	if (opts.severity) params.set('severity', opts.severity);
	const qs = params.toString();
	return fetchJSON(`/api/events${qs ? '?' + qs : ''}`);
}

export async function triggerScan(subnet = '') {
	const res = await fetch(`${BASE}/api/scans`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ subnet })
	});
	return res.json();
}
