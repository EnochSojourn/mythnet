import { writable, derived } from 'svelte/store';

export const devices = writable([]);
export const stats = writable({ total_devices: 0, online_devices: 0, total_ports: 0, total_scans: 0 });
export const selectedDeviceId = writable(null);
export const scanning = writable(false);

export const selectedDevice = derived(
	[devices, selectedDeviceId],
	([$devices, $id]) => {
		if (!$id) return null;
		return $devices.find(d => d.id === $id) || null;
	}
);
