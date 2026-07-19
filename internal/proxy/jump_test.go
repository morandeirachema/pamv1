package proxy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"golang.org/x/crypto/ssh"
)

// genKeyPEM returns a fresh ed25519 key as OpenSSH PEM plus its signer.
func genKeyPEM(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), signer
}

// startBastion runs a minimal SSH bastion that accepts wantUser with wantKey and
// tunnels direct-tcpip channels to their requested destination.
func startBastion(t *testing.T, wantUser string, wantKey ssh.PublicKey) string {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == wantUser && bytes.Equal(key.Marshal(), wantKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("bastion: denied")
		},
	}
	cfg.AddHostKey(mustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveBastion(conn, cfg)
		}
	}()
	return ln.Addr().String()
}

func serveBastion(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "bastion: only direct-tcpip")
			continue
		}
		var d struct {
			DestAddr string
			DestPort uint32
			SrcAddr  string
			SrcPort  uint32
		}
		_ = ssh.Unmarshal(nc.ExtraData(), &d)
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		up, err := net.Dial("tcp", net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort))))
		if err != nil {
			ch.Close()
			continue
		}
		go func() { io.Copy(ch, up); ch.Close() }()
		go func() { io.Copy(up, ch); up.Close() }()
	}
}

// TestJumpHostConnector proves the proxy reaches an SSH target through a bastion:
// the target is dialed via a direct-tcpip tunnel over the jump host.
func TestJumpHostConnector(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	jumpPEM, jumpSigner := genKeyPEM(t)
	bastionAddr := startBastion(t, "jumpuser", jumpSigner.PublicKey())

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Jump: &proxy.JumpConfig{Addr: bastionAddr, User: "jumpuser", KeyPEM: jumpPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("run")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("through-bastion exec: out=%q err=%v", out, err)
	}
}
