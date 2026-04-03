package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mythnet/mythnet/internal/config"
	"github.com/mythnet/mythnet/internal/db"
)

// Manager coordinates the mesh networking layer.
type Manager struct {
	cfg       *config.Config
	store     *db.Store
	identity  *Identity
	gossip    *Gossip
	repServer *ReplicationServer
	repClient *ReplicationClient
	logger    *slog.Logger
}

// NewManager creates and initializes the mesh manager.
// Returns nil if mesh is disabled.
func NewManager(cfg *config.Config, store *db.Store, logger *slog.Logger) (*Manager, error) {
	if !cfg.Mesh.Enabled {
		return nil, nil
	}

	identity, err := LoadOrCreateIdentity(cfg.Mesh.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	logger.Info("mesh identity loaded", "node_id", identity.NodeID, "type", cfg.Mesh.NodeType)

	// Install oplog hook so all Store mutations are logged for replication
	nodeID := identity.NodeID
	store.SetOplogHook(func(table, op string, data any) {
		store.AppendOplog(table, op, data, nodeID)
	})

	return &Manager{
		cfg:      cfg,
		store:    store,
		identity: identity,
		logger:   logger,
	}, nil
}

// Run starts gossip, replication server, and sync loop. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	// Start replication server (mTLS)
	m.repServer = NewReplicationServer(m.store, m.identity, m.cfg.Mesh.NodeType, m.logger)
	go func() {
		if err := m.repServer.Run(ctx, m.cfg.Mesh.ReplicaAddr); err != nil {
			m.logger.Error("mesh replication server failed", "error", err)
		}
	}()

	// Start gossip
	meta := NodeMeta{
		NodeID:      m.identity.NodeID,
		NodeType:    m.cfg.Mesh.NodeType,
		Version:     "0.4.0",
		APIPort:     m.cfg.Server.Port,
		ReplicaAddr: m.cfg.Mesh.ReplicaAddr,
	}

	gossip, err := NewGossip(m.cfg.Mesh.BindAddr, m.cfg.Mesh.Secret, meta, m.store, m.logger)
	if err != nil {
		return err
	}
	m.gossip = gossip
	m.gossip.OnJoin = func(p *Peer) {
		go m.syncWithPeers() // Immediate sync on new peer
	}

	// Join seed nodes
	if len(m.cfg.Mesh.Join) > 0 {
		joined, err := m.gossip.Join(m.cfg.Mesh.Join)
		if err != nil {
			m.logger.Warn("mesh join partial", "joined", joined, "error", err)
		} else {
			m.logger.Info("mesh joined", "peers", joined)
		}
	}

	// Start replication client
	m.repClient = NewReplicationClient(m.store, m.identity, m.logger)

	// Periodic sync loop
	go m.syncLoop(ctx)

	// Periodic oplog pruning
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.store.PruneOplog(48 * time.Hour)
			}
		}
	}()

	<-ctx.Done()
	m.gossip.Stop()
	return nil
}

func (m *Manager) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncWithPeers()
		}
	}
}

func (m *Manager) syncWithPeers() {
	for _, peer := range m.gossip.Peers() {
		if peer.Meta.ReplicaAddr == "" {
			continue
		}

		switch m.cfg.Mesh.NodeType {
		case "sensor":
			// Sensors push to full nodes
			if peer.Meta.NodeType == "full" {
				if err := m.repClient.PushTo(peer.Meta.ReplicaAddr); err != nil {
					m.logger.Debug("mesh push failed", "peer", peer.Meta.NodeID, "error", err)
				}
			}
		case "full":
			// Full nodes pull from other full nodes
			if peer.Meta.NodeType == "full" {
				if err := m.repClient.SyncFrom(peer.Meta.ReplicaAddr); err != nil {
					m.logger.Debug("mesh sync failed", "peer", peer.Meta.NodeID, "error", err)
				}
			}
		}
	}
}

// NodeID returns this node's unique identifier.
func (m *Manager) NodeID() string {
	return m.identity.NodeID
}

// PeerCount returns the number of known mesh peers.
func (m *Manager) PeerCount() int {
	if m.gossip == nil {
		return 0
	}
	return m.gossip.MemberCount() - 1 // Exclude self
}
