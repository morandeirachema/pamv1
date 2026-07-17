package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// GenerateHostKey returns a fresh ephemeral ed25519 host key. Ephemeral keys
// change on every restart, which trips client host-key pinning; persist one
// with PAM_SSH_HOST_KEY for anything but demos.
func GenerateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// LoadOrCreateHostKey parses an OpenSSH private key from path. If path is
// empty an ephemeral key is generated; if path is set but missing, a new key
// is generated and written there (0600) so it stays stable across restarts.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return GenerateHostKey()
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encodePEM(block), 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}
