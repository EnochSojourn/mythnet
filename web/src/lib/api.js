const BASE = '';

function authHeaders() {
	const creds = localStorage.getItem('mythnet_creds');
	const h = {};
	if (creds) h['Authorization'] = 'Basic ' + creds;
	return h;
}

async function fetchJSON(path) {
	const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
	if (res.status === 401) {
		// Clear stale creds and force re-login
		localStorage.removeItem('mythnet_creds');
		window.location.reload();
		throw new Error('Unauthorized');
	}
	if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
	return res.json();
}

async function postJSON(path, body) {
	const res = await fetch(`${BASE}${path}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...authHeaders() },
		body: JSON.stringify(body)
	});
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
	if (opts.q) params.set('q', opts.q);
	const qs = params.toString();
	return fetchJSON(`/api/events${qs ? '?' + qs : ''}`);
}

export function triggerScan(subnet = '') {
	return postJSON('/api/scans', { subnet });
}

export function getSettings() {
	return fetchJSON('/api/settings');
}

export function putSettings(settings) {
	return fetch(`${BASE}/api/settings`, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json', ...authHeaders() },
		body: JSON.stringify(settings)
	}).then(r => r.json());
}

export { authHeaders };
