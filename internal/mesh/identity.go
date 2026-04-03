package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Identity holds the node's cryptographic identity for mesh communication.
type Identity struct {
	NodeID  string
	Key     *ecdsa.PrivateKey
	Cert    tls.Certificate
	CertPEM []byte
}

// LoadOrCreateIdentity loads an existing identity or generates a new one.
func LoadOrCreateIdentity(dataDir string) (*Identity, error) {
	dir := filepath.Join(dataDir, "identity")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}

	keyPath := filepath.Join(dir, "node.key")
	certPath := filepath.Join(dir, "node.crt")

	if _, err := os.Stat(keyPath); err == nil {
		return loadIdentity(keyPath, certPath)
	}

	return generateIdentity(keyPath, certPath)
}

func generateIdentity(keyPath, certPath string) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubBytes)
	nodeID := hex.EncodeToString(hash[:8])

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "mythnet-" + nodeID,
			Organization: []string{"MythNet Mesh"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, err
	}

	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &Identity{NodeID: nodeID, Key: key, Cert: tlsCert, CertPEM: certPEM}, nil
}

func loadIdentity(keyPath, certPath string) (*Identity, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubBytes)
	nodeID := hex.EncodeToString(hash[:8])

	return &Identity{NodeID: nodeID, Key: key, Cert: tlsCert, CertPEM: certPEM}, nil
}

// ServerTLSConfig returns a TLS config for the replication server (requires client cert).
func (id *Identity) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig returns a TLS config for connecting to replication peers.
func (id *Identity) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{id.Cert},
		InsecureSkipVerify: true, // Peer identity verified via gossip membership
		MinVersion:         tls.VersionTLS13,
	}
}
