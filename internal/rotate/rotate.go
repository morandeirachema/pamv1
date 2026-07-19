// Package rotate implements the credential-lifecycle connectors: changing a
// privileged account's secret on the real target (rotation) and checking that a
// vaulted secret still authenticates (reconciliation). Both operations run over
// the same secure protocols the session proxy uses (SSH, WinRM) so a rotation is
// verifiable end-to-end.
//
// A Rotator sets a new secret on the target; a Verifier proves a secret still
// works. The SSH and WinRM connectors implement both. Password generation lives
// here too, producing strong secrets from a shell-safe alphabet so an injected
// password can never break the command that sets it.
package rotate

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

// Rotator changes username's secret on target from oldSecret to newSecret.
// Implementations authenticate with oldSecret (the account rotating itself must
// be privileged enough to set its own password).
type Rotator interface {
	Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error
}

// Verifier reports whether secret still authenticates username to target
// (nil = in sync). A non-nil error is drift or an unreachable target.
type Verifier interface {
	Verify(ctx context.Context, target store.Target, username, secret string) error
}

// --- password generation ---

// Password alphabets. Symbols are restricted to characters that are safe both
// on a shell command line (WinRM `net user`) and in an SSH stdin payload, so a
// generated password can never inject into the rotation command.
const (
	lowers  = "abcdefghijkmnopqrstuvwxyz"
	uppers  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "-_.~"
	allPw   = lowers + uppers + digits + symbols
)

// GeneratePassword returns a cryptographically strong password of length n
// (minimum 12) guaranteed to contain at least one lowercase, uppercase, digit
// and symbol — satisfying typical Windows/Linux complexity policies.
func GeneratePassword(n int) (string, error) {
	if n < 12 {
		n = 12
	}
	out := make([]byte, n)
	// Guarantee one of each category, then fill the rest from the full set.
	cats := []string{lowers, uppers, digits, symbols}
	for i, set := range cats {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	for i := len(cats); i < n; i++ {
		c, err := pick(allPw)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	// Shuffle so the guaranteed characters are not always at the front.
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// pick returns a cryptographically random byte drawn from set.
func pick(set string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[idx.Int64()], nil
}

// shuffle performs a crypto-random Fisher–Yates shuffle in place.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		ji := int(j.Int64())
		b[i], b[ji] = b[ji], b[i]
	}
	return nil
}

// --- SSH connector (Linux/Unix targets) ---

// SSHConnector rotates and verifies password credentials over SSH. Rotation
// runs RotateCommand (default "chpasswd") and feeds it "user:newpass\n" on
// stdin — the new password never appears on the command line, so it cannot be
// shell-injected. The rotating account must be able to set its own password
// (root, or a sudoer with an appropriate RotateCommand such as "sudo chpasswd").
type SSHConnector struct {
	// RotateCommand reads "username:newpassword\n" on stdin. Default "chpasswd".
	RotateCommand string
	// Timeout bounds the dial + command. Default 15s.
	Timeout time.Duration
	// HostKeyCallback pins the upstream host key. Default InsecureIgnoreHostKey
	// (documented gap; supply a known_hosts callback for production).
	HostKeyCallback ssh.HostKeyCallback
}

// timeout returns the configured dial+command timeout, or 15s when unset.
func (c SSHConnector) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

// dial opens an SSH client to the target as username using password auth,
// applying the configured host-key callback (InsecureIgnoreHostKey by default).
func (c SSHConnector) dial(target store.Target, username, secret string) (*ssh.Client, error) {
	cb := c.HostKeyCallback
	if cb == nil {
		cb = ssh.InsecureIgnoreHostKey()
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(secret)},
		HostKeyCallback: cb,
		Timeout:         c.timeout(),
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), cfg)
}

// Verify dials the target and completes an SSH handshake with secret; success
// means the credential still authenticates.
func (c SSHConnector) Verify(_ context.Context, target store.Target, username, secret string) error {
	client, err := c.dial(target, username, secret)
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	_ = client.Close()
	return nil
}

// Rotate connects with oldSecret and sets the password to newSecret via
// RotateCommand.
func (c SSHConnector) Rotate(_ context.Context, target store.Target, username, oldSecret, newSecret string) error {
	if strings.ContainsAny(username, ":\n\r") {
		return fmt.Errorf("rotate: unsafe username")
	}
	client, err := c.dial(target, username, oldSecret)
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	cmd := c.RotateCommand
	if cmd == "" {
		cmd = "chpasswd"
	}
	sess.Stdin = strings.NewReader(username + ":" + newSecret + "\n")
	if out, err := sess.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("rotate command failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// --- WinRM connector (Windows targets) ---

// WinRMConnector rotates and verifies password credentials over WinRM using a
// winrm.Runner. Rotation runs `net user <user> <newpass>`; the generated
// password is drawn from a shell-safe alphabet so it is safe on the cmd line.
type WinRMConnector struct {
	Runner winrm.Runner
}

// Verify runs a trivial command; a clean exit means the credential authenticates.
func (c WinRMConnector) Verify(ctx context.Context, target store.Target, username, secret string) error {
	res, err := c.Runner.Run(ctx, target.Host, target.Port, username, secret, "cmd /c ver")
	if err != nil {
		return fmt.Errorf("winrm auth failed: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("winrm verify exit %d", res.ExitCode)
	}
	return nil
}

// Rotate sets the account's password with `net user` (the account must be able
// to change its own password, or the connector account must be privileged).
func (c WinRMConnector) Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error {
	if strings.ContainsAny(username, " \"\n\r") {
		return fmt.Errorf("rotate: unsafe username")
	}
	cmd := fmt.Sprintf("net user %s %s", username, newSecret)
	res, err := c.Runner.Run(ctx, target.Host, target.Port, username, oldSecret, cmd)
	if err != nil {
		return fmt.Errorf("winrm rotate failed: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("net user exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}
