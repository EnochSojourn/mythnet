package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// Poller periodically polls HTTP endpoints on discovered devices
// and stores status changes as Markdown events.
type Poller struct {
	store    *db.Store
	logger   *slog.Logger
	client   *http.Client
	interval time.Duration
	// Dedup: track last seen status per device:port
	lastStatus map[string]int
	mu         sync.Mutex
}

// NewPoller creates a new API poller.
func NewPoller(store *db.Store, logger *slog.Logger, interval time.Duration) *Poller {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &Poller{
		store:    store,
		logger:   logger,
		interval: interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		lastStatus: make(map[string]int),
	}
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.logger.Info("API poller starting", "interval", p.interval)

	// Wait for scanner to populate devices before first poll
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}

	p.pollAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAll(ctx)
		}
	}
}

func (p *Poller) pollAll(ctx context.Context) {
	devices, err := p.store.ListDevices()
	if err != nil {
		return
	}

	for _, dev := range devices {
		if !dev.IsOnline {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		ports, _ := p.store.GetDevicePorts(dev.ID)
		for _, port := range ports {
			if isWebPort(port.Port) {
				p.pollHTTP(ctx, dev, port.Port)
			}
		}
	}
}

func (p *Poller) pollHTTP(ctx context.Context, dev *db.Device, port int) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, dev.IP, port)
	key := fmt.Sprintf("%s:%d", dev.ID, port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "MythNet/0.3.0")

	resp, err := p.client.Do(req)
	if err != nil {
		// Check if previously was up — if so, record the down event
		p.mu.Lock()
		prev, hadPrev := p.lastStatus[key]
		if hadPrev && prev > 0 {
			p.lastStatus[key] = -1
			p.mu.Unlock()
			p.storeEvent(dev, url, 0, nil, "", "Device endpoint unreachable")
		} else {
			p.mu.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)

	// Dedup: only store if status changed from last poll
	p.mu.Lock()
	prev, hadPrev := p.lastStatus[key]
	p.lastStatus[key] = resp.StatusCode
	p.mu.Unlock()

	if hadPrev && prev == resp.StatusCode {
		return // No change
	}

	// Collect interesting headers
	headers := map[string]string{}
	for _, h := range []string{"Server", "Content-Type", "X-Powered-By", "WWW-Authenticate"} {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	p.storeEvent(dev, url, resp.StatusCode, headers, bodyStr, "")
}

func (p *Poller) storeEvent(dev *db.Device, url string, status int, headers map[string]string, body, note string) {
	now := time.Now()

	var event TelemetryEvent
	if status == 0 {
		event = TelemetryEvent{
			DeviceID: dev.ID,
			Source:   "api_poll",
			Severity: "warning",
			Title:    fmt.Sprintf("Endpoint Down — %s", url),
			BodyMD:   fmt.Sprintf("## Endpoint Unreachable\n\n**Device:** `%s`  \n**URL:** `%s`  \n**Time:** %s\n\n%s\n", dev.IP, url, now.Format(time.RFC3339), note),
			Tags:     []string{"api", "down"},
		}
	} else {
		// Limit body preview for Markdown
		preview := body
		if len(preview) > 300 {
			preview = preview[:300]
		}
		event = FormatAPIResponse(dev.IP, url, status, headers, preview, now)
		event.DeviceID = dev.ID
	}

	p.store.InsertEvent(&db.Event{
		DeviceID:   event.DeviceID,
		Source:     event.Source,
		Severity:   event.Severity,
		Title:      event.Title,
		BodyMD:     event.BodyMD,
		RawData:    event.RawData,
		ReceivedAt: now,
		Tags:       JoinTags(event.Tags),
	})
}

func isWebPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 9090
}
