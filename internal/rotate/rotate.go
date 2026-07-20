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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

// GenerateSSHKey returns a fresh ed25519 private key in OpenSSH PEM format,
// suitable for vaulting as a new ssh_key credential.
func GenerateSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(block)), nil
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

// dialAuth opens an SSH client to the target as username with the given auth
// method, applying the configured host-key callback (InsecureIgnoreHostKey by
// default).
func (c SSHConnector) dialAuth(target store.Target, username string, auth ssh.AuthMethod) (*ssh.Client, error) {
	cb := c.HostKeyCallback
	if cb == nil {
		cb = ssh.InsecureIgnoreHostKey()
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: cb,
		Timeout:         c.timeout(),
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), cfg)
}

// dial opens an SSH client to the target as username using password auth.
func (c SSHConnector) dial(target store.Target, username, secret string) (*ssh.Client, error) {
	return c.dialAuth(target, username, ssh.Password(secret))
}

// authMethod picks public-key auth when secret is a PEM private key (an ssh_key
// credential) and password auth otherwise, so Verify works for both credential
// types instead of always presenting an ssh_key as a password.
func authMethod(secret string) (ssh.AuthMethod, error) {
	if strings.Contains(secret, "PRIVATE KEY") {
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(secret), nil
}

// execGuard bounds a remote command by c.timeout() (and honors ctx), closing the
// session to unblock a CombinedOutput that a wedged target would otherwise hang
// on forever. The returned func stops the guard and must be deferred.
func (c SSHConnector) execGuard(ctx context.Context, sess io.Closer) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				sess.Close()
			}
		case <-done:
		}
	}()
	return func() { cancel(); close(done) }
}

// Verify dials the target and completes an SSH handshake with secret (a password
// or an ssh_key PEM); success means the credential still authenticates.
func (c SSHConnector) Verify(_ context.Context, target store.Target, username, secret string) error {
	auth, err := authMethod(secret)
	if err != nil {
		return err
	}
	client, err := c.dialAuth(target, username, auth)
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	_ = client.Close()
	return nil
}

// Rotate connects with oldSecret and sets the password to newSecret via
// RotateCommand.
func (c SSHConnector) Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error {
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
	defer c.execGuard(ctx, sess)()

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

// ExecResult is the outcome of a one-shot remote command.
type ExecResult struct {
	ExitCode int
	Output   string
}

// Exec dials the target as username with secret (an ssh_key PEM or a password),
// runs a single non-interactive command, and returns its combined output and
// exit code. It is the broker's ssh_exec primitive: one-shot, no PTY/shell,
// bounded by the connector timeout. A non-zero remote exit is a result, not a
// transport error; only dial/session failures return err.
func (c SSHConnector) Exec(ctx context.Context, target store.Target, username, secret, command string) (ExecResult, error) {
	auth, err := authMethod(secret)
	if err != nil {
		return ExecResult{}, err
	}
	client, err := c.dialAuth(target, username, auth)
	if err != nil {
		return ExecResult{}, fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return ExecResult{}, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	defer c.execGuard(ctx, sess)()

	out, err := sess.CombinedOutput(command)
	res := ExecResult{Output: string(out)}
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("ssh exec failed: %w", err)
	}
	return res, nil
}

// KeyRotator rotates an SSH **key** credential: it authenticates with the old
// private key and installs a freshly generated public key, so the old key stops
// working. Only the SSH connector implements it.
type KeyRotator interface {
	RotateKey(ctx context.Context, target store.Target, username, oldPrivPEM, newPrivPEM string) error
}

// RotateKey connects with the old private key and replaces the account's
// authorized_keys with the public key derived from newPrivPEM (the new private
// key is what the vault will store). The old key no longer authenticates.
func (c SSHConnector) RotateKey(ctx context.Context, target store.Target, username, oldPrivPEM, newPrivPEM string) error {
	oldSigner, err := ssh.ParsePrivateKey([]byte(oldPrivPEM))
	if err != nil {
		return fmt.Errorf("parse current ssh key: %w", err)
	}
	newSigner, err := ssh.ParsePrivateKey([]byte(newPrivPEM))
	if err != nil {
		return fmt.Errorf("parse new ssh key: %w", err)
	}
	authLine := ssh.MarshalAuthorizedKey(newSigner.PublicKey())                           // "ssh-ed25519 AAAA...\n"
	oldLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(oldSigner.PublicKey()))) // base64 blob only alphabet — shell-safe in single quotes

	client, err := c.dialAuth(target, username, ssh.PublicKeys(oldSigner))
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	defer c.execGuard(ctx, sess)()

	// Remove only the OLD PAM key line and append the new one from stdin, so any
	// other keys on the account (operator, emergency, automation) are preserved.
	sess.Stdin = strings.NewReader(string(authLine))
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "+
		"{ grep -vF '%s' ~/.ssh/authorized_keys; cat; } > ~/.ssh/authorized_keys.pamnew && "+
		"mv ~/.ssh/authorized_keys.pamnew ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", oldLine)
	if out, err := sess.CombinedOutput(cmd); err != nil {
		return fmt.Errorf("install authorized_keys failed: %w: %s", err, strings.TrimSpace(string(out)))
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
	// /y auto-confirms net.exe's ">14 characters ... continue? (Y/N)" prompt,
	// which a 24-char generated password always triggers and which would otherwise
	// hang a non-interactive WinRM session.
	cmd := fmt.Sprintf("net user %s %s /y", username, newSecret)
	res, err := c.Runner.Run(ctx, target.Host, target.Port, username, oldSecret, cmd)
	if err != nil {
		return fmt.Errorf("winrm rotate failed: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("net user exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}
