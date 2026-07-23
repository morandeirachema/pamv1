// Package mfa implements time-based one-time passwords (TOTP, RFC 6238) for
// multi-factor authentication. It uses the standard authenticator-app profile
// (HMAC-SHA1, 6 digits, 30-second period) so Google Authenticator, Microsoft
// Authenticator, 1Password, etc. work out of the box.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 is mandated by RFC 6238 TOTP for authenticator-app compatibility
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30 * time.Second
	// skew allows codes from the adjacent time steps to tolerate clock drift.
	skew = 1
)

// b32 is unpadded, upper-case base32 — the encoding authenticator apps expect.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random base32 TOTP secret (160 bits).
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// decodeSecret decodes a base32 TOTP secret, tolerating lower case and surrounding whitespace.
func decodeSecret(secret string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
}

// hotp is the HMAC-based OTP (RFC 4226) for a counter.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// Code returns the TOTP code for secret at time t.
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix()/int64(period.Seconds()))), nil
}

// Validate reports whether code is a valid TOTP for secret at time t, allowing
// ±skew time steps. The comparison is constant-time.
func Validate(secret, code string, t time.Time) bool {
	_, ok := ValidateStep(secret, code, t)
	return ok
}

// ValidateStep is like Validate but also returns the matched time-step counter,
// so callers can record it and reject a later reuse of the same code within the
// skew window (anti-replay). The comparison is constant-time.
func ValidateStep(secret, code string, t time.Time) (int64, bool) {
	key, err := decodeSecret(secret)
	if err != nil || len(code) != digits {
		return 0, false
	}
	base := t.Unix() / int64(period.Seconds())
	for d := -skew; d <= skew; d++ {
		step := base + int64(d)
		want := hotp(key, uint64(step))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// GenerateRecoveryCodes returns n single-use backup codes formatted as
// "xxxxx-xxxxx" (base32, ~50 bits each). Store only their hashes.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		s := strings.ToLower(b32.EncodeToString(buf)) // 13 chars
		codes = append(codes, s[:5]+"-"+s[5:10])
	}
	return codes, nil
}

// ProvisioningURI builds an otpauth:// URI (for a QR code / manual entry) that
// enrolls the secret in an authenticator app.
func ProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(int(period.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
