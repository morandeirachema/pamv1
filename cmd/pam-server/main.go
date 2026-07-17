// pam-server runs the pamv1 API and portal.
//
// Utility flags:
//
//	-genkey   print a fresh vault master key (PAM_MASTER_KEY) and exit
//	-hashkey  read an emergency break-glass key from stdin and print its
//	          SHA-256 hex (PAM_BREAK_GLASS_KEY_HASH); the plaintext key is
//	          then sealed offline (envelope / safe) and never stored.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

func main() {
	genkey := flag.Bool("genkey", false, "print a new vault master key and exit")
	hashkey := flag.Bool("hashkey", false, "read a break-glass key from stdin, print its SHA-256 hex and exit")
	flag.Parse()

	switch {
	case *genkey:
		key, err := vault.GenerateMasterKey()
		if err != nil {
			fatal(err)
		}
		fmt.Println(key)
	case *hashkey:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(err)
		}
		sum := sha256.Sum256([]byte(strings.TrimSpace(string(data))))
		fmt.Println(hex.EncodeToString(sum[:]))
	default:
		if err := run(); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pam-server:", err)
	os.Exit(1)
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logging.Setup(cfg.LogLevel, cfg.LogFormat)
	log := logging.Component("server")

	v, err := vault.New(cfg.MasterKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "memory" {
		log.Warn("using ephemeral in-memory store; data is lost on restart (demo mode)")
		st = memstore.New()
	} else {
		st, err = pgstore.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
	}
	defer st.Close()

	resolver, err := auth.NewResolver(st, cfg.APIKey, cfg.BreakGlassKeyHash)
	if err != nil {
		return err
	}

	handler, err := api.New(st, v, resolver)
	if err != nil {
		return err
	}

	if cfg.SSHAddr != "off" {
		hostKey, err := proxy.LoadOrCreateHostKey(cfg.SSHHostKeyPath)
		if err != nil {
			return fmt.Errorf("ssh host key: %w", err)
		}
		px, err := proxy.New(st, v, resolver, proxy.Config{
			HostKey:      hostKey,
			RecordingDir: cfg.RecordingDir,
		})
		if err != nil {
			return err
		}
		go func() {
			if err := px.ListenAndServe(ctx, cfg.SSHAddr); err != nil {
				log.Error("ssh proxy stopped", "err", err)
			}
		}()
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("pam-server listening", "addr", cfg.ListenAddr,
		"breakglass", cfg.BreakGlassKeyHash != "", "log_level", cfg.LogLevel)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
