package mesh

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/mythnet/mythnet/internal/db"
)

// NodeMeta is exchanged between mesh peers via gossip.
type NodeMeta struct {
	NodeID      string `json:"id"`
	NodeType    string `json:"type"`
	Version     string `json:"version"`
	APIPort     int    `json:"api_port"`
	ReplicaAddr string `json:"replica_addr"`
}

// Peer represents a discovered mesh peer.
type Peer struct {
	Name    string
	Address string
	Meta    NodeMeta
}

// Gossip wraps HashiCorp memberlist for mesh peer discovery.
type Gossip struct {
	list   *memberlist.Memberlist
	meta   NodeMeta
	store  *db.Store
	logger *slog.Logger

	mu    sync.RWMutex
	peers map[string]*Peer

	OnJoin  func(*Peer)
	OnLeave func(string)
}

// NewGossip creates and starts the gossip layer.
func NewGossip(bindAddr, secret string, meta NodeMeta, store *db.Store, logger *slog.Logger) (*Gossip, error) {
	g := &Gossip{
		meta:   meta,
		store:  store,
		logger: logger,
		peers:  make(map[string]*Peer),
	}

	cfg := memberlist.DefaultLANConfig()
	cfg.Name = meta.NodeID
	cfg.Delegate = &gossipDelegate{g: g}
	cfg.Events = &eventDelegate{g: g}
	cfg.LogOutput = nil // Suppress memberlist's own logging

	// Parse bind address
	parts := strings.Split(bindAddr, ":")
	if len(parts) == 2 {
		cfg.BindAddr = parts[0]
		if p, err := strconv.Atoi(parts[1]); err == nil {
			cfg.BindPort = p
			cfg.AdvertisePort = p
		}
	}

	// Encrypt gossip with shared secret
	if secret != "" {
		key := sha256.Sum256([]byte(secret))
		cfg.SecretKey = key[:]
	}

	list, err := memberlist.Create(cfg)
	if err != nil {
		return nil, fmt.Errorf("create memberlist: %w", err)
	}
	g.list = list

	logger.Info("gossip started", "node_id", meta.NodeID, "bind", bindAddr)
	return g, nil
}

// Join attempts to join existing mesh peers.
func (g *Gossip) Join(addrs []string) (int, error) {
	return g.list.Join(addrs)
}

// Stop shuts down the gossip layer.
func (g *Gossip) Stop() error {
	return g.list.Shutdown()
}

// Peers returns all known mesh peers (excluding self).
func (g *Gossip) Peers() []*Peer {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Peer, 0, len(g.peers))
	for _, p := range g.peers {
		out = append(out, p)
	}
	return out
}

// MemberCount returns the total number of mesh members.
func (g *Gossip) MemberCount() int {
	return g.list.NumMembers()
}

// --- Delegates ---

type gossipDelegate struct {
	g *Gossip
}

func (d *gossipDelegate) NodeMeta(limit int) []byte {
	data, _ := json.Marshal(d.g.meta)
	return data
}
func (d *gossipDelegate) NotifyMsg([]byte)                           {}
func (d *gossipDelegate) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (d *gossipDelegate) LocalState(join bool) []byte                { return nil }
func (d *gossipDelegate) MergeRemoteState(buf []byte, join bool)     {}

type eventDelegate struct {
	g *Gossip
}

func (e *eventDelegate) NotifyJoin(node *memberlist.Node) {
	var meta NodeMeta
	json.Unmarshal(node.Meta, &meta)

	if meta.NodeID == e.g.meta.NodeID {
		return
	}

	peer := &Peer{Name: node.Name, Address: node.Address(), Meta: meta}

	e.g.mu.Lock()
	e.g.peers[node.Name] = peer
	e.g.mu.Unlock()

	e.g.logger.Info("mesh peer joined", "node_id", meta.NodeID, "type", meta.NodeType, "addr", node.Address())

	// Track in database
	e.g.store.UpsertMeshNode(&db.MeshNode{
		NodeID: meta.NodeID, Name: node.Name, Address: node.Address(),
		NodeType: meta.NodeType, LastSeen: time.Now().Format(time.RFC3339),
	})

	if e.g.OnJoin != nil {
		e.g.OnJoin(peer)
	}
}

func (e *eventDelegate) NotifyLeave(node *memberlist.Node) {
	e.g.mu.Lock()
	delete(e.g.peers, node.Name)
	e.g.mu.Unlock()

	e.g.logger.Info("mesh peer left", "node", node.Name)
	e.g.store.RemoveMeshNode(node.Name)

	if e.g.OnLeave != nil {
		e.g.OnLeave(node.Name)
	}
}

func (e *eventDelegate) NotifyUpdate(node *memberlist.Node) {
	var meta NodeMeta
	json.Unmarshal(node.Meta, &meta)

	e.g.mu.Lock()
	if p, ok := e.g.peers[node.Name]; ok {
		p.Meta = meta
	}
	e.g.mu.Unlock()
}
