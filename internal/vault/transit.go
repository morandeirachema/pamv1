package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TransitKEK wraps data keys with HashiCorp Vault's Transit secrets engine
// (https://developer.hashicorp.com/vault/docs/secrets/transit) over HTTPS. The
// key material never leaves Vault: Wrap/Unwrap round-trip the data key through
// the Transit encrypt/decrypt endpoints. This is the vendor-aligned production
// KEK; use HTTPS for PAM_KEK_TRANSIT_ADDR.
type TransitKEK struct {
	addr  string
	token string
	key   string
	hc    *http.Client
}

// NewTransitKEK builds a Transit-backed KEK. addr, token and key are all
// required; addr has any trailing slash trimmed.
func NewTransitKEK(addr, token, key string) (*TransitKEK, error) {
	if addr == "" || token == "" || key == "" {
		return nil, errors.New("vault: vault-transit KEK requires PAM_KEK_TRANSIT_ADDR, PAM_KEK_TRANSIT_TOKEN and PAM_KEK_TRANSIT_KEY")
	}
	return &TransitKEK{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		key:   key,
		hc:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// ID reports the provider identifier, "vault-transit:<key>".
func (k *TransitKEK) ID() string { return "vault-transit:" + k.key }

// Wrap encrypts the data key via Transit's encrypt endpoint and returns the
// Transit ciphertext string ("vault:v1:...") as bytes.
func (k *TransitKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := k.call(ctx, "/v1/transit/encrypt/"+k.key,
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Data.Ciphertext == "" {
		return nil, errors.New("vault: transit returned empty ciphertext")
	}
	return []byte(resp.Data.Ciphertext), nil
}

// Unwrap decrypts a Transit ciphertext back to the data key via the decrypt
// endpoint.
func (k *TransitKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := k.call(ctx, "/v1/transit/decrypt/"+k.key,
		map[string]string{"ciphertext": string(wrapped)}, &resp)
	if err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault: transit decode plaintext: %w", err)
	}
	return dek, nil
}

// call POSTs body as JSON to the Transit path with the Vault token header and
// decodes a 2xx response into out; non-2xx status returns an error with the body.
func (k *TransitKEK) call(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.addr+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", k.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("vault: transit %s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
