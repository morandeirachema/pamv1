package shamir

import (
	"bytes"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := []byte("break-glass-emergency-key-2026")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}
	// A single share must not reveal the secret.
	if bytes.Contains(shares[0][:len(shares[0])-1], secret) {
		t.Fatal("a share leaked the secret")
	}

	// Any 3 shares reconstruct the secret; different subsets all agree.
	subsets := [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}, {1, 3, 4}}
	for _, sub := range subsets {
		got, err := Combine([][]byte{shares[sub[0]], shares[sub[1]], shares[sub[2]]})
		if err != nil {
			t.Fatalf("combine %v: %v", sub, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("subset %v reconstructed %q, want %q", sub, got, secret)
		}
	}

	// Using all 5 also works.
	if got, _ := Combine(shares); !bytes.Equal(got, secret) {
		t.Fatalf("combining all shares: %q", got)
	}
}

func TestFewerThanThresholdIsWrong(t *testing.T) {
	secret := []byte("0123456789abcdef")
	shares, _ := Split(secret, 5, 3)
	// Two shares (below threshold) must NOT reconstruct the secret.
	got, err := Combine(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, secret) {
		t.Fatal("threshold-1 shares should not reveal the secret")
	}
}

func TestCorruptedShareFails(t *testing.T) {
	secret := []byte("sensitive")
	shares, _ := Split(secret, 3, 3)
	shares[1][0] ^= 0xFF // corrupt one y-value
	if got, _ := Combine(shares); bytes.Equal(got, secret) {
		t.Fatal("a corrupted share should not reconstruct the secret")
	}
}

func TestSplitValidation(t *testing.T) {
	if _, err := Split(nil, 5, 3); err == nil {
		t.Fatal("empty secret should error")
	}
	if _, err := Split([]byte("x"), 2, 5); err == nil {
		t.Fatal("parts < threshold should error")
	}
	if _, err := Split([]byte("x"), 3, 1); err == nil {
		t.Fatal("threshold < 2 should error")
	}
}
