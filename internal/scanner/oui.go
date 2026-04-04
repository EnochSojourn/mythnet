package scanner

import "strings"

// LookupVendor returns the vendor name for a MAC address using the OUI prefix.
func LookupVendor(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) < 8 {
		return ""
	}
	prefix := mac[:8]
	if vendor, ok := ouiDB[prefix]; ok {
		return vendor
	}
	return ""
}

// ouiDB maps the first 3 bytes (OUI) of MAC addresses to vendor names.
var ouiDB = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple",
	"00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
	"00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
	"00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
	"00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple",
	"00:22:41": "Apple", "00:23:12": "Apple", "00:23:6C": "Apple",
	"00:23:DF": "Apple", "00:24:36": "Apple", "00:25:00": "Apple",
	"00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple",
	"00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple",
	"00:50:E4": "Apple", "04:0C:CE": "Apple", "04:15:52": "Apple",
	"04:26:65": "Apple", "04:48:9A": "Apple", "04:52:F3": "Apple",
	"04:54:53": "Apple", "04:69:F8": "Apple", "04:F1:3E": "Apple",
	"04:F7:E4": "Apple",

	// Cisco
	"00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
	"00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
	"00:01:97": "Cisco", "00:02:3D": "Cisco", "00:02:4A": "Cisco",
	"00:02:4B": "Cisco", "00:02:7D": "Cisco", "00:02:7E": "Cisco",
	"00:02:B9": "Cisco", "00:02:BA": "Cisco", "00:02:FC": "Cisco",
	"00:02:FD": "Cisco",

	// Dell
	"00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
	"00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
	"00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
	"00:15:C5": "Dell", "00:18:8B": "Dell", "00:19:B9": "Dell",
	"00:1A:A0": "Dell", "00:1C:23": "Dell", "00:1D:09": "Dell",
	"00:1E:4F": "Dell", "00:1E:C9": "Dell", "00:21:70": "Dell",
	"00:21:9B": "Dell", "00:22:19": "Dell", "00:24:E8": "Dell",
	"00:25:64": "Dell", "00:26:B9": "Dell",

	// HP / HPE
	"00:01:E6": "HP", "00:01:E7": "HP", "00:02:A5": "HP",
	"00:04:EA": "HP", "00:08:02": "HP", "00:08:83": "HP",
	"00:0A:57": "HP", "00:0B:CD": "HP", "00:0D:9D": "HP",
	"00:0E:7F": "HP", "00:0F:20": "HP", "00:0F:61": "HP",
	"00:10:83": "HP", "00:11:0A": "HP", "00:11:85": "HP",
	"00:12:79": "HP", "00:13:21": "HP", "00:14:38": "HP",
	"00:14:C2": "HP", "00:15:60": "HP", "00:16:35": "HP",
	"00:17:08": "HP", "00:17:A4": "HP", "00:18:FE": "HP",
	"00:19:BB": "HP", "00:1A:4B": "HP", "00:1B:78": "HP",
	"00:1C:C4": "HP", "00:1E:0B": "HP", "00:1F:29": "HP",
	"00:21:5A": "HP", "00:22:64": "HP", "00:23:7D": "HP",
	"00:24:81": "HP", "00:25:B3": "HP", "00:26:55": "HP",
	"3C:D9:2B": "HP",

	// Intel
	"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
	"00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel",
	"00:0E:35": "Intel", "00:11:11": "Intel", "00:12:F0": "Intel",
	"00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel",
	"00:13:E8": "Intel", "00:15:00": "Intel", "00:15:17": "Intel",
	"00:16:6F": "Intel", "00:16:76": "Intel", "00:16:EA": "Intel",
	"00:16:EB": "Intel", "00:18:DE": "Intel", "00:19:D1": "Intel",
	"00:19:D2": "Intel", "00:1B:21": "Intel", "00:1B:77": "Intel",
	"00:1C:BF": "Intel", "00:1C:C0": "Intel", "00:1D:E0": "Intel",
	"00:1D:E1": "Intel", "00:1E:64": "Intel", "00:1E:65": "Intel",
	"00:1F:3B": "Intel", "00:1F:3C": "Intel", "00:20:7B": "Intel",
	"00:21:5C": "Intel", "00:21:5D": "Intel", "00:21:6A": "Intel",
	"00:21:6B": "Intel", "00:22:43": "Intel", "00:22:FA": "Intel",
	"00:22:FB": "Intel", "00:23:14": "Intel", "00:23:15": "Intel",
	"00:24:D6": "Intel", "00:24:D7": "Intel", "00:26:C6": "Intel",
	"00:26:C7": "Intel", "00:27:10": "Intel",

	// Samsung
	"00:00:F0": "Samsung", "00:07:AB": "Samsung", "00:09:18": "Samsung",
	"00:0D:AE": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
	"00:13:77": "Samsung", "00:15:99": "Samsung", "00:15:B9": "Samsung",
	"00:16:32": "Samsung", "00:16:6B": "Samsung", "00:16:DB": "Samsung",
	"00:17:C9": "Samsung", "00:17:D5": "Samsung", "00:18:AF": "Samsung",
	"00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung",
	"00:1D:F6": "Samsung", "00:1E:75": "Samsung", "00:1F:CC": "Samsung",
	"00:21:19": "Samsung", "00:21:D1": "Samsung", "00:23:39": "Samsung",
	"00:23:99": "Samsung", "00:23:D6": "Samsung", "00:24:54": "Samsung",
	"00:24:90": "Samsung", "00:25:66": "Samsung", "00:26:37": "Samsung",
	"00:26:5D": "Samsung",

	// Google / Nest
	"18:D6:C7": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
	"94:EB:2C": "Google", "A4:77:33": "Google", "F4:F5:D8": "Google",
	"F4:F5:E8": "Google",

	// Amazon
	"00:FC:8B": "Amazon", "0C:47:C9": "Amazon", "10:CE:A9": "Amazon",
	"14:91:82": "Amazon", "18:74:2E": "Amazon", "34:D2:70": "Amazon",
	"38:F7:3D": "Amazon", "40:B4:CD": "Amazon", "44:65:0D": "Amazon",
	"4C:EF:C0": "Amazon", "50:DC:E7": "Amazon", "50:F5:DA": "Amazon",
	"68:37:E9": "Amazon", "68:54:FD": "Amazon", "6C:56:97": "Amazon",
	"74:75:48": "Amazon", "74:C2:46": "Amazon", "84:D6:D0": "Amazon",
	"A0:02:DC": "Amazon", "AC:63:BE": "Amazon", "B4:7C:9C": "Amazon",
	"F0:27:2D": "Amazon", "F0:D2:F1": "Amazon", "FC:65:DE": "Amazon",

	// Microsoft
	"00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
	"00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
	"00:22:48": "Microsoft", "00:25:AE": "Microsoft", "00:50:F2": "Microsoft",
	"28:18:78": "Microsoft", "7C:1E:52": "Microsoft",

	// Netgear
	"00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
	"00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
	"00:1F:33": "Netgear", "00:22:3F": "Netgear", "00:24:B2": "Netgear",
	"00:26:F2": "Netgear", "20:4E:7F": "Netgear", "2C:B0:5D": "Netgear",
	"30:46:9A": "Netgear", "44:94:FC": "Netgear", "6C:B0:CE": "Netgear",
	"84:1B:5E": "Netgear", "A0:04:60": "Netgear", "C4:3D:C7": "Netgear",

	// TP-Link
	"00:27:19": "TP-Link", "14:CC:20": "TP-Link", "14:CF:92": "TP-Link",
	"18:A6:F7": "TP-Link", "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link",
	"54:C8:0F": "TP-Link", "60:E3:27": "TP-Link", "64:70:02": "TP-Link",
	"6C:5A:B0": "TP-Link", "74:DA:38": "TP-Link", "90:F6:52": "TP-Link",
	"98:DA:C4": "TP-Link", "AC:84:C6": "TP-Link", "B0:4E:26": "TP-Link",
	"C0:25:E9": "TP-Link", "D4:6E:0E": "TP-Link", "E8:DE:27": "TP-Link",
	"EC:08:6B": "TP-Link", "F4:F2:6D": "TP-Link",

	// Ubiquiti
	"00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
	"18:E8:29": "Ubiquiti", "24:5A:4C": "Ubiquiti", "24:A4:3C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti", "74:83:C2": "Ubiquiti",
	"78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
	"DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti", "FC:EC:DA": "Ubiquiti",

	// Raspberry Pi
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",

	// Linksys
	"00:04:5A": "Linksys", "00:06:25": "Linksys", "00:0C:41": "Linksys",
	"00:0F:66": "Linksys", "00:12:17": "Linksys", "00:13:10": "Linksys",
	"00:14:BF": "Linksys", "00:16:B6": "Linksys", "00:18:39": "Linksys",
	"00:18:F8": "Linksys", "00:1A:70": "Linksys", "00:1C:10": "Linksys",
	"00:1D:7E": "Linksys", "00:21:29": "Linksys", "00:22:6B": "Linksys",
	"00:25:9C": "Linksys",

	// ASUS
	"00:0C:6E": "ASUS", "00:0E:A6": "ASUS", "00:11:2F": "ASUS",
	"00:11:D8": "ASUS", "00:13:D4": "ASUS", "00:15:F2": "ASUS",
	"00:17:31": "ASUS", "00:18:F3": "ASUS", "00:1A:92": "ASUS",
	"00:1B:FC": "ASUS", "00:1D:60": "ASUS", "00:1E:8C": "ASUS",
	"00:1F:C6": "ASUS", "00:22:15": "ASUS", "00:23:54": "ASUS",
	"00:24:8C": "ASUS", "00:26:18": "ASUS", "04:D4:C4": "ASUS",
	"08:60:6E": "ASUS", "10:BF:48": "ASUS", "14:DA:E9": "ASUS",
	"2C:4D:54": "ASUS", "30:85:A9": "ASUS", "38:D5:47": "ASUS",
	"50:46:5D": "ASUS", "54:04:A6": "ASUS", "60:45:CB": "ASUS",

	// D-Link
	"00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:0F:3D": "D-Link",
	"00:11:95": "D-Link", "00:13:46": "D-Link", "00:15:E9": "D-Link",
	"00:17:9A": "D-Link", "00:19:5B": "D-Link", "00:1B:11": "D-Link",
	"00:1C:F0": "D-Link", "00:1E:58": "D-Link", "00:21:91": "D-Link",
	"00:22:B0": "D-Link", "00:24:01": "D-Link", "00:26:5A": "D-Link",

	// Sonos
	"00:0E:58": "Sonos", "5C:AA:FD": "Sonos", "78:28:CA": "Sonos",
	"94:9F:3E": "Sonos", "B8:E9:37": "Sonos",

	// Roku
	"08:05:81": "Roku", "10:59:32": "Roku", "20:EF:BD": "Roku",
	"B0:A7:37": "Roku", "B8:3E:59": "Roku", "C8:3A:6B": "Roku",
	"D4:E2:2F": "Roku", "D8:31:34": "Roku",

	// VMware
	"00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
	"00:50:56": "VMware",

	// Synology
	"00:11:32": "Synology",

	// QNAP
	"00:08:9B": "QNAP",

	// Aruba / HPE Aruba
	"00:0B:86": "Aruba", "00:1A:1E": "Aruba", "00:24:6C": "Aruba",
	"04:BD:88": "Aruba", "18:64:72": "Aruba", "20:4C:03": "Aruba",
	"24:DE:C6": "Aruba", "40:E3:D6": "Aruba", "6C:F3:7F": "Aruba",
	"84:D4:7E": "Aruba", "AC:A3:1E": "Aruba", "D8:C7:C8": "Aruba",

	// Juniper
	"00:05:85": "Juniper", "00:10:DB": "Juniper", "00:12:1E": "Juniper",
	"00:14:F6": "Juniper", "00:17:CB": "Juniper", "00:19:E2": "Juniper",
	"00:1D:B5": "Juniper", "00:1F:12": "Juniper", "00:21:59": "Juniper",
	"00:22:83": "Juniper", "00:23:9C": "Juniper", "00:24:DC": "Juniper",
	"00:26:88": "Juniper",

	// Fortinet
	"00:09:0F": "Fortinet", "08:5B:0E": "Fortinet",
	"70:4C:A5": "Fortinet", "90:6C:AC": "Fortinet",

	// Lenovo
	"00:06:1B": "Lenovo", "00:09:2D": "Lenovo", "00:0A:E4": "Lenovo",
	"00:12:FE": "Lenovo", "00:1A:6B": "Lenovo", "00:21:CC": "Lenovo",
	"00:26:2D": "Lenovo", "28:D2:44": "Lenovo", "50:7B:9D": "Lenovo",
	"54:EE:75": "Lenovo", "70:F3:95": "Lenovo", "C8:5B:76": "Lenovo",
	"E8:2A:44": "Lenovo",

	// Huawei
	"00:E0:FC": "Huawei", "00:18:82": "Huawei", "00:1E:10": "Huawei",
	"00:25:68": "Huawei", "00:25:9E": "Huawei", "04:02:1F": "Huawei",
	"04:C0:6F": "Huawei", "04:F9:38": "Huawei", "08:19:A6": "Huawei",
	"0C:96:BF": "Huawei", "10:1B:54": "Huawei", "10:47:80": "Huawei",
	"14:B9:68": "Huawei", "20:0B:C7": "Huawei", "20:A6:80": "Huawei",
	"20:F3:A3": "Huawei", "24:09:95": "Huawei", "28:31:52": "Huawei",

	// Xiaomi
	"00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "0C:1D:AF": "Xiaomi",
	"10:2A:B3": "Xiaomi", "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi",
	"28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi", "34:CE:00": "Xiaomi",
	"38:A4:ED": "Xiaomi", "50:64:2B": "Xiaomi", "58:44:98": "Xiaomi",
	"64:09:80": "Xiaomi", "74:23:44": "Xiaomi", "78:11:DC": "Xiaomi",
	"98:FA:E3": "Xiaomi", "A8:6B:7C": "Xiaomi", "C4:0B:CB": "Xiaomi",
	"F0:B4:29": "Xiaomi", "F8:A4:5F": "Xiaomi", "FC:64:BA": "Xiaomi",

	// Espressif (ESP32/ESP8266 — IoT)
	"24:0A:C4": "Espressif", "24:6F:28": "Espressif", "24:B2:DE": "Espressif",
	"2C:3A:E8": "Espressif", "30:AE:A4": "Espressif", "3C:61:05": "Espressif",
	"3C:71:BF": "Espressif", "40:F5:20": "Espressif", "4C:11:AE": "Espressif",
	"54:43:B2": "Espressif", "5C:CF:7F": "Espressif", "60:01:94": "Espressif",
	"68:C6:3A": "Espressif", "7C:9E:BD": "Espressif", "80:7D:3A": "Espressif",
	"84:0D:8E": "Espressif", "84:CC:A8": "Espressif", "8C:AA:B5": "Espressif",
	"94:B5:55": "Espressif", "A0:20:A6": "Espressif", "A4:CF:12": "Espressif",
	"AC:67:B2": "Espressif", "B4:E6:2D": "Espressif", "BC:DD:C2": "Espressif",
	"C4:4F:33": "Espressif", "CC:50:E3": "Espressif", "DC:4F:22": "Espressif",
	"EC:FA:BC": "Espressif", "F4:CF:A2": "Espressif",

	// Hikvision
	"28:57:BE": "Hikvision", "44:19:B6": "Hikvision", "54:C4:15": "Hikvision",
	"8C:E7:48": "Hikvision", "A4:14:37": "Hikvision", "BC:AD:28": "Hikvision",
	"C0:56:E3": "Hikvision", "E0:50:8B": "Hikvision",

	// Dahua
	"3C:EF:8C": "Dahua", "40:2C:76": "Dahua",

	// AV equipment
	"00:05:A6": "Extron", "00:10:7F": "Crestron", "00:0E:DD": "Shure",

	// Smart home
	"00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
	"34:3E:A4": "Ring", "50:32:37": "Ring",

	// MikroTik
	"00:0C:42": "MikroTik", "48:8F:5A": "MikroTik",
	"4C:5E:0C": "MikroTik", "6C:3B:6B": "MikroTik",
	"74:4D:28": "MikroTik", "B8:69:F4": "MikroTik",
	"CC:2D:E0": "MikroTik", "D4:CA:6D": "MikroTik",
	"E4:8D:8C": "MikroTik",

	// eero mesh routers
	"00:AB:48": "eero",

	// Ring (additional)
	"B0:09:DA": "Ring",

	// Peloton
	"AC:04:0B": "Peloton",

	// Texas Instruments (IoT chipsets)
	"90:9A:77": "Texas Instruments",

	// AMPAK (IoT/smart home chipsets)
	"9C:B8:B4": "AMPAK", "C0:F5:35": "AMPAK",

	// Gaoshengda (IoT chipsets)
	"28:7B:11": "Gaoshengda",

	// Qingdao/Tuya (smart home)
	"38:64:07": "Tuya",
}
