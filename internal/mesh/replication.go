package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mythnet/mythnet/internal/db"
)

// ReplicationServer serves the mTLS replication API.
type ReplicationServer struct {
	store    *db.Store
	identity *Identity
	nodeType string
	logger   *slog.Logger
	server   *http.Server
}

// NewReplicationServer creates a new replication server.
func NewReplicationServer(store *db.Store, identity *Identity, nodeType string, logger *slog.Logger) *ReplicationServer {
	return &ReplicationServer{store: store, identity: identity, nodeType: nodeType, logger: logger}
}

// Run starts the mTLS replication server.
func (rs *ReplicationServer) Run(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mesh/status", rs.handleStatus)
	mux.HandleFunc("/mesh/sync", rs.handleSync)
	mux.HandleFunc("/mesh/push", rs.handlePush)

	rs.server = &http.Server{Handler: mux, TLSConfig: rs.identity.ServerTLSConfig()}

	rs.logger.Info("mesh replication server starting", "addr", addr, "tls", "mTLS")

	go func() {
		<-ctx.Done()
		rs.server.Close()
	}()

	ln, err := tls.Listen("tcp", addr, rs.server.TLSConfig)
	if err != nil {
		return fmt.Errorf("replication listen %s: %w", addr, err)
	}

	err = rs.server.Serve(ln)
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

func (rs *ReplicationServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	seq, _ := rs.store.LatestOplogSeq()
	json.NewEncoder(w).Encode(map[string]any{
		"node_id":    rs.identity.NodeID,
		"node_type":  rs.nodeType,
		"latest_seq": seq,
	})
}

func (rs *ReplicationServer) handleSync(w http.ResponseWriter, r *http.Request) {
	if rs.nodeType == "sensor" {
		http.Error(w, "sensor nodes don't serve sync", http.StatusForbidden)
		return
	}

	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	ops, err := rs.store.GetOpsAfter(after, 1000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ops == nil {
		ops = []db.OplogEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ops)
}

func (rs *ReplicationServer) handlePush(w http.ResponseWriter, r *http.Request) {
	if rs.nodeType == "sensor" {
		http.Error(w, "sensor nodes don't accept push", http.StatusForbidden)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	var ops []db.OplogEntry
	if err := json.Unmarshal(body, &ops); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	applied := 0
	for _, op := range ops {
		if err := applyOp(rs.store, op); err != nil {
			rs.logger.Error("mesh: apply op failed", "error", err)
			continue
		}
		applied++
	}

	json.NewEncoder(w).Encode(map[string]int{"applied": applied})
}

func applyOp(store *db.Store, op db.OplogEntry) error {
	switch op.Operation {
	case "upsert_device":
		var d db.Device
		if err := json.Unmarshal([]byte(op.Data), &d); err != nil {
			return err
		}
		return store.UpsertDevice(&d)
	case "upsert_port":
		var p db.Port
		if err := json.Unmarshal([]byte(op.Data), &p); err != nil {
			return err
		}
		return store.UpsertPort(&p)
	case "insert_event":
		var e db.Event
		if err := json.Unmarshal([]byte(op.Data), &e); err != nil {
			return err
		}
		return store.InsertEvent(&e)
	}
	return nil
}

// ReplicationClient syncs data with mesh peers over mTLS.
type ReplicationClient struct {
	store    *db.Store
	identity *Identity
	logger   *slog.Logger
	client   *http.Client
}

// NewReplicationClient creates a new replication client.
func NewReplicationClient(store *db.Store, identity *Identity, logger *slog.Logger) *ReplicationClient {
	return &ReplicationClient{
		store:    store,
		identity: identity,
		logger:   logger,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: identity.ClientTLSConfig()},
			Timeout:   30 * time.Second,
		},
	}
}

// SyncFrom pulls new operations from a Full Node peer.
func (rc *ReplicationClient) SyncFrom(replicaAddr string) error {
	localSeq, _ := rc.store.LatestOplogSeq()

	url := fmt.Sprintf("https://%s/mesh/sync?after=%d", replicaAddr, localSeq)
	resp, err := rc.client.Get(url)
	if err != nil {
		return fmt.Errorf("sync from %s: %w", replicaAddr, err)
	}
	defer resp.Body.Close()

	var ops []db.OplogEntry
	if err := json.NewDecoder(resp.Body).Decode(&ops); err != nil {
		return err
	}

	applied := 0
	for _, op := range ops {
		if err := applyOp(rc.store, op); err == nil {
			applied++
		}
	}

	if applied > 0 {
		rc.logger.Info("mesh: synced operations", "from", replicaAddr, "applied", applied)
	}
	return nil
}

// PushTo sends local operations to a Full Node peer.
func (rc *ReplicationClient) PushTo(replicaAddr string) error {
	// Get peer's latest sequence
	statusURL := fmt.Sprintf("https://%s/mesh/status", replicaAddr)
	resp, err := rc.client.Get(statusURL)
	if err != nil {
		return fmt.Errorf("push status %s: %w", replicaAddr, err)
	}
	defer resp.Body.Close()

	var status struct {
		LatestSeq int64 `json:"latest_seq"`
	}
	json.NewDecoder(resp.Body).Decode(&status)

	// Get our ops after their sequence
	ops, err := rc.store.GetOpsAfter(status.LatestSeq, 1000)
	if err != nil || len(ops) == 0 {
		return err
	}

	data, _ := json.Marshal(ops)
	pushURL := fmt.Sprintf("https://%s/mesh/push", replicaAddr)
	resp2, err := rc.client.Post(pushURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("push to %s: %w", replicaAddr, err)
	}
	resp2.Body.Close()

	rc.logger.Info("mesh: pushed operations", "to", replicaAddr, "count", len(ops))
	return nil
}
