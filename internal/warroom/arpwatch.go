package warroom

import (
	"context"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/db"
	"github.com/mythnet/mythnet/internal/scanner"
)

// ARPWatcher continuously monitors the ARP table for new devices.
// Fires an alert the moment an unknown MAC appears.
type ARPWatcher struct {
	store  *db.Store
	logger *slog.Logger
	known  map[string]string // MAC → IP
}

func NewARPWatcher(store *db.Store, logger *slog.Logger) *ARPWatcher {
	return &ARPWatcher{store: store, logger: logger, known: make(map[string]string)}
}

func (w *ARPWatcher) Run(ctx context.Context) {
	// Seed known MACs from current devices
	devices, _ := w.store.ListDevices()
	for _, d := range devices {
		if d.MAC != "" {
			w.known[d.MAC] = d.IP
		}
	}

	w.logger.Info("ARP watcher started", "known_macs", len(w.known))

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *ARPWatcher) check() {
	arpTable := scanner.ReadARPTable()
	now := time.Now()

	for ip, mac := range arpTable {
		if _, known := w.known[mac]; !known {
			w.known[mac] = ip
			vendor := scanner.LookupVendor(mac)

			w.logger.Warn("NEW DEVICE detected on network",
				"ip", ip, "mac", mac, "vendor", vendor)

			w.store.InsertEvent(&db.Event{
				Source:     "arp_watch",
				Severity:   "warning",
				Title:      "New device joined: " + ip + " (" + mac + ")",
				BodyMD:     "## New Device Detected\n\n**IP:** `" + ip + "`  \n**MAC:** `" + mac + "`  \n**Vendor:** " + vendor + "  \n**Time:** " + now.Format(time.RFC3339) + "\n\n> A device not previously seen has appeared on the network.",
				ReceivedAt: now,
				Tags:       "arp,new_device,security",
			})
		}
	}
}
