package warroom

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// DeviceController sends commands to controllable devices.
type DeviceController struct {
	store  *db.Store
	client *http.Client
}

func NewDeviceController(store *db.Store) *DeviceController {
	return &DeviceController{
		store:  store,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// ControlResult is the response from a device command.
type ControlResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// SendCommand routes a command to the appropriate device API.
func (dc *DeviceController) SendCommand(deviceID, command string, params map[string]string) ControlResult {
	device, err := dc.store.GetDevice(deviceID)
	if err != nil {
		return ControlResult{Success: false, Message: "device not found"}
	}

	ports, _ := dc.store.GetDevicePorts(deviceID)
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p.Port] = true
	}

	// Roku ECP (port 8060)
	if portSet[8060] {
		return dc.rokuCommand(device.IP, command, params)
	}

	// Google Cast (port 8008)
	if portSet[8008] {
		return dc.castCommand(device.IP, command, params)
	}

	return ControlResult{Success: false, Message: "no controllable API found on this device"}
}

// GetCapabilities returns what commands are available for a device.
func (dc *DeviceController) GetCapabilities(deviceID string) map[string]any {
	ports, _ := dc.store.GetDevicePorts(deviceID)
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p.Port] = true
	}

	caps := map[string]any{"controllable": false, "apis": []string{}, "commands": []string{}}

	if portSet[8060] {
		caps["controllable"] = true
		caps["apis"] = append(caps["apis"].([]string), "Roku ECP")
		caps["commands"] = []string{
			"power_off", "power_on", "home", "back", "play", "pause",
			"volume_up", "volume_down", "volume_mute",
			"up", "down", "left", "right", "select",
			"launch_app", "device_info", "active_app", "apps",
		}
	}

	if portSet[8008] {
		caps["controllable"] = true
		caps["apis"] = append(caps["apis"].([]string), "Google Cast")
		caps["commands"] = []string{
			"device_info", "reboot", "volume_set", "bluetooth_status",
		}
	}

	return caps
}

// --- Roku ECP ---

func (dc *DeviceController) rokuCommand(ip, cmd string, params map[string]string) ControlResult {
	base := fmt.Sprintf("http://%s:8060", ip)

	switch cmd {
	case "device_info":
		body, err := dc.httpGet(base + "/query/device-info")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "device info retrieved", Data: body}

	case "apps":
		body, err := dc.httpGet(base + "/query/apps")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "app list retrieved", Data: body}

	case "active_app":
		body, err := dc.httpGet(base + "/query/active-app")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "active app retrieved", Data: body}

	case "launch_app":
		appID := params["app_id"]
		if appID == "" {
			return ControlResult{Success: false, Message: "app_id required"}
		}
		_, err := dc.httpPost(base+"/launch/"+appID, "")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "app launched: " + appID}

	case "power_off":
		dc.httpPost(base+"/keypress/PowerOff", "")
		return ControlResult{Success: true, Message: "power off sent"}
	case "power_on":
		dc.httpPost(base+"/keypress/PowerOn", "")
		return ControlResult{Success: true, Message: "power on sent"}
	case "home":
		dc.httpPost(base+"/keypress/Home", "")
		return ControlResult{Success: true, Message: "home pressed"}
	case "back":
		dc.httpPost(base+"/keypress/Back", "")
		return ControlResult{Success: true, Message: "back pressed"}
	case "play":
		dc.httpPost(base+"/keypress/Play", "")
		return ControlResult{Success: true, Message: "play pressed"}
	case "pause":
		dc.httpPost(base+"/keypress/Pause", "")
		return ControlResult{Success: true, Message: "pause pressed"}
	case "volume_up":
		dc.httpPost(base+"/keypress/VolumeUp", "")
		return ControlResult{Success: true, Message: "volume up"}
	case "volume_down":
		dc.httpPost(base+"/keypress/VolumeDown", "")
		return ControlResult{Success: true, Message: "volume down"}
	case "volume_mute":
		dc.httpPost(base+"/keypress/VolumeMute", "")
		return ControlResult{Success: true, Message: "mute toggled"}
	case "up", "down", "left", "right", "select":
		key := strings.Title(cmd)
		dc.httpPost(base+"/keypress/"+key, "")
		return ControlResult{Success: true, Message: key + " pressed"}

	default:
		return ControlResult{Success: false, Message: "unknown Roku command: " + cmd}
	}
}

// --- Google Cast ---

func (dc *DeviceController) castCommand(ip, cmd string, params map[string]string) ControlResult {
	base := fmt.Sprintf("http://%s:8008", ip)

	switch cmd {
	case "device_info":
		body, err := dc.httpGet(base + "/setup/eureka_info?options=detail")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		var info map[string]any
		json.Unmarshal([]byte(body), &info)
		return ControlResult{Success: true, Message: "device info", Data: info}

	case "reboot":
		_, err := dc.httpPost(base+"/setup/reboot", `{"params":"now"}`)
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "reboot command sent"}

	case "volume_set":
		level := params["level"]
		if level == "" {
			return ControlResult{Success: false, Message: "level required (0-1.0)"}
		}
		_, err := dc.httpPost(base+"/setup/assistant/set_volume", `{"volume":`+level+`}`)
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		return ControlResult{Success: true, Message: "volume set to " + level}

	case "bluetooth_status":
		body, err := dc.httpGet(base + "/setup/bluetooth/status")
		if err != nil {
			return ControlResult{Success: false, Message: err.Error()}
		}
		var bt map[string]any
		json.Unmarshal([]byte(body), &bt)
		return ControlResult{Success: true, Message: "bluetooth status", Data: bt}

	default:
		return ControlResult{Success: false, Message: "unknown Cast command: " + cmd}
	}
}

func (dc *DeviceController) httpGet(url string) (string, error) {
	resp, err := dc.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	return string(body), nil
}

func (dc *DeviceController) httpPost(url, body string) (string, error) {
	resp, err := dc.client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	return string(b), nil
}
