package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// encodePEM serializes a PEM block to its textual (memory) encoding.
func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// recordChain links session recordings into a tamper-evident hash chain: each
// recording's chain hash is SHA-256(previousChainHash || fileHash). To alter one
// recording undetected you would have to rewrite every later chain hash too. The
// head is persisted to a file so the chain survives restarts.
type recordChain struct {
	mu   sync.Mutex
	path string
	head []byte
}

// newRecordChain opens the hash chain stored under dir, loading any persisted
// head so the chain continues across restarts.
func newRecordChain(dir string) *recordChain {
	c := &recordChain{path: filepath.Join(dir, ".chain")}
	if b, err := os.ReadFile(c.path); err == nil {
		if h, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil {
			c.head = h
		}
	}
	return c
}

// append advances the chain with a recording's file hash (hex) and returns the
// new chain hash (hex).
func (c *recordChain) append(fileSHAHex string) string {
	fh, err := hex.DecodeString(fileSHAHex)
	if err != nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sum := sha256.Sum256(append(append([]byte{}, c.head...), fh...))
	c.head = sum[:]
	_ = os.MkdirAll(filepath.Dir(c.path), 0o700)
	_ = os.WriteFile(c.path, []byte(hex.EncodeToString(c.head)), 0o600)
	return hex.EncodeToString(c.head)
}

// Recording writes a session's terminal output in asciicast v2 format while
// hashing the same bytes, so the audit trail can store a tamper-evident
// SHA-256 of the recording. Safe for concurrent Write.
type Recording struct {
	path   string
	f      *os.File
	enc    *json.Encoder
	hasher hash.Hash
	start  time.Time

	mu sync.Mutex
	n  int64
}

// newRecording creates a .cast file under dir (named from a sanitized title),
// writes the asciicast v2 header and returns a Recording that hashes every byte
// it writes so its contents can be verified later.
func newRecording(dir, title string, now time.Time) (*Recording, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, sanitize(title)+".cast")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(f, hasher))
	header := map[string]any{
		"version":   2,
		"width":     80,
		"height":    24,
		"timestamp": now.Unix(),
		"title":     title,
	}
	r := &Recording{path: path, f: f, enc: enc, hasher: hasher, start: now}
	if err := enc.Encode(header); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// Write records p as an asciicast "o" (output) event.
func (r *Recording) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ev := []any{time.Since(r.start).Seconds(), "o", string(p)}
	if err := r.enc.Encode(ev); err != nil {
		return 0, err
	}
	r.n += int64(len(p))
	return len(p), nil
}

// Close flushes the file and returns the recording path, byte count and the
// hex SHA-256 of the file's contents.
func (r *Recording) Close() (path, sha256hex string, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.f.Close()
	return r.path, hex.EncodeToString(r.hasher.Sum(nil)), r.n
}

// sanitize replaces any character outside [A-Za-z0-9-_.@] with '-' so the
// result is safe to use as a filename.
func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '@':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
