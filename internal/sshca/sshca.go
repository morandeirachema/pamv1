// Package sshca implements a Zero Standing Privilege (ZSP) SSH certificate
// authority. Instead of storing a long-lived password or private key for a
// privileged account, pamv1 signs a short-lived SSH *user certificate*
// just-in-time for each proxied session. The target trusts only the pamv1 CA
// (its public key installed as an OpenSSH TrustedUserCAKeys), so the account
// has no standing secret at all — the certificate is minted fresh per session
// and expires in minutes. This is the Teleport / CyberArk ZSP model applied to
// pamv1's existing JIT proxy chokepoint.
//
// The CA private key never signs anything but short-TTL user certificates, and
// the per-session client keypair is generated in memory, used for one dial, and
// discarded — no secret is ever persisted for the account.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// encodePEM serializes a PEM block to its textual encoding.
func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// clockSkew is how far before "now" a minted certificate becomes valid, to
// tolerate small clock differences between pamv1 and the target.
const clockSkew = 1 * time.Minute

// CertAuthority signs short-lived SSH user certificates. It holds the CA
// private key and a monotonically increasing serial counter (unique per issued
// certificate, for audit correlation).
type CertAuthority struct {
	signer ssh.Signer
	serial atomic.Uint64
}

// New builds a CertAuthority from an existing SSH signer (the CA private key).
func New(signer ssh.Signer) *CertAuthority {
	ca := &CertAuthority{signer: signer}
	// Seed the serial from the wall clock so certificate serials do not restart
	// from a low value (and collide with a prior run) across restarts. The value
	// is only for audit correlation, not security.
	ca.serial.Store(uint64(time.Now().UnixNano()))
	return ca
}

// LoadOrCreate parses an OpenSSH CA private key from path, generating and
// persisting a fresh ed25519 key (0600) when the file does not yet exist — so
// the CA public key stays stable across restarts (targets pin it). An empty
// path is an error: a ZSP CA must be persistent to be useful.
func LoadOrCreate(path string) (*CertAuthority, error) {
	if path == "" {
		return nil, errors.New("sshca: a persistent key path is required")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		signer, perr := ssh.ParsePrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("sshca: parse CA key %q: %w", path, perr)
		}
		return New(signer), nil
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
		return nil, fmt.Errorf("sshca: write CA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return New(signer), nil
}

// PublicKey returns the CA's SSH public key (what a target trusts).
func (ca *CertAuthority) PublicKey() ssh.PublicKey { return ca.signer.PublicKey() }

// AuthorizedKey returns the CA public key as an OpenSSH authorized_keys line
// (trailing newline trimmed), ready to drop into a target's TrustedUserCAKeys.
func (ca *CertAuthority) AuthorizedKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())))
}

// Fingerprint returns the CA public key's SHA-256 fingerprint (for display).
func (ca *CertAuthority) Fingerprint() string {
	return ssh.FingerprintSHA256(ca.signer.PublicKey())
}

// IssueUser mints a short-lived SSH user certificate for principal, valid for
// ttl, and returns a signer that authenticates with it. A fresh ephemeral
// keypair backs each certificate: the private key lives only in the returned
// signer (one dial, then discarded), so no standing secret exists for the
// account. keyID is stamped into the certificate (pamv1 records the actor and
// target there) for audit correlation on the target's sshd logs. The returned
// certificate is also handed back so the caller can audit its serial/validity.
func (ca *CertAuthority) IssueUser(principal string, ttl time.Duration, keyID string) (ssh.Signer, *ssh.Certificate, error) {
	if principal == "" {
		return nil, nil, errors.New("sshca: empty certificate principal")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          ca.serial.Add(1),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: standardExtensions(),
		},
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, nil, fmt.Errorf("sshca: sign certificate: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: cert signer: %w", err)
	}
	return certSigner, cert, nil
}

// standardExtensions returns the permissive extension set OpenSSH grants a user
// certificate by default, so an interactive session (pty, shell, exec) works.
func standardExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}
