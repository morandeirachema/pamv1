// Package shamir implements Shamir's Secret Sharing over GF(2^8) — the scheme
// used for pamv1's M-of-N break-glass quorum: the emergency key is split into N
// shares, and any M of them reconstruct it (fewer reveal nothing).
package shamir

import (
	"crypto/rand"
	"errors"
)

// GF(2^8) log/exp tables with generator 3 and the AES reduction polynomial.
var logTable, expTable [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		x = mulNoTable(x, 3)
	}
	expTable[255] = 1 // exp has period 255; wrap for index arithmetic
}

// mulNoTable multiplies in GF(2^8) without tables (used only to build them).
func mulNoTable(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[(int(logTable[a])+int(logTable[b]))%255]
}

func div(a, b byte) byte {
	// b != 0 by construction (distinct x-coordinates)
	if a == 0 {
		return 0
	}
	return expTable[(int(logTable[a])-int(logTable[b])+255)%255]
}

// evaluate computes the polynomial (coeffs low→high) at x.
func evaluate(coeffs []byte, x byte) byte {
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = mul(result, x) ^ coeffs[i]
	}
	return result
}

// Split divides secret into `parts` shares of which any `threshold` reconstruct
// it. Each share is len(secret)+1 bytes: the y-values followed by its x-coord.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	switch {
	case len(secret) == 0:
		return nil, errors.New("shamir: empty secret")
	case parts < threshold:
		return nil, errors.New("shamir: parts < threshold")
	case threshold < 2:
		return nil, errors.New("shamir: threshold must be >= 2")
	case parts > 255:
		return nil, errors.New("shamir: parts must be <= 255")
	}

	shares := make([][]byte, parts)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][len(secret)] = byte(i + 1) // x-coordinate 1..parts (never 0)
	}

	coeffs := make([]byte, threshold)
	for b := range secret {
		coeffs[0] = secret[b]
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			shares[i][b] = evaluate(coeffs, byte(i+1))
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from shares (any threshold of the originals).
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least 2 shares")
	}
	n := len(shares[0])
	if n < 2 {
		return nil, errors.New("shamir: malformed share")
	}
	xs := make([]byte, len(shares))
	seen := make(map[byte]bool)
	for i, s := range shares {
		if len(s) != n {
			return nil, errors.New("shamir: shares differ in length")
		}
		x := s[n-1]
		if x == 0 || seen[x] {
			return nil, errors.New("shamir: invalid or duplicate share")
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, n-1)
	ys := make([]byte, len(shares))
	for b := 0; b < n-1; b++ {
		for i := range shares {
			ys[i] = shares[i][b]
		}
		secret[b] = interpolateAtZero(xs, ys)
	}
	return secret, nil
}

// interpolateAtZero does Lagrange interpolation at x=0.
func interpolateAtZero(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		num, den := byte(1), byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = mul(num, xs[j])       // (0 - x_j) == x_j in GF(2^8)
			den = mul(den, xs[i]^xs[j]) // x_i - x_j == x_i XOR x_j
		}
		result ^= mul(ys[i], div(num, den))
	}
	return result
}
