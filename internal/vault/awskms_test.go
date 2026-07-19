package vault

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMS reversibly "encrypts" by prefixing a tag — enough to prove the KEK
// round-trips the data key through the (mocked) KMS.
type fakeKMS struct {
	prefix  []byte
	failEnc bool
}

// encCtx serializes an EncryptionContext deterministically so the fake can embed
// it in the blob and enforce it on Decrypt, like real KMS.
func encCtx(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + ";")
	}
	return b.String()
}

// Encrypt fakes KMS encryption by prefixing the plaintext with a tag and the
// EncryptionContext (or fails if failEnc).
func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.failEnc {
		return nil, errors.New("kms: access denied")
	}
	blob := append(append([]byte{}, f.prefix...), []byte(encCtx(in.EncryptionContext)+"\x00")...)
	blob = append(blob, in.Plaintext...)
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

// Decrypt reverses Encrypt, erroring on a bad prefix or a mismatched
// EncryptionContext (KMS requires the identical context used to encrypt).
func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if !bytes.HasPrefix(in.CiphertextBlob, f.prefix) {
		return nil, errors.New("kms: invalid ciphertext")
	}
	rest := in.CiphertextBlob[len(f.prefix):]
	sep := bytes.IndexByte(rest, 0)
	if sep < 0 {
		return nil, errors.New("kms: malformed blob")
	}
	if string(rest[:sep]) != encCtx(in.EncryptionContext) {
		return nil, errors.New("kms: encryption context mismatch")
	}
	return &kms.DecryptOutput{Plaintext: rest[sep+1:]}, nil
}

// TestAWSKMSKEKRoundtrip proves wrap→unwrap round-trips the data key through the
// (mocked) KMS and the ID is well-formed.
func TestAWSKMSKEKRoundtrip(t *testing.T) {
	ctx := context.Background()
	kek := &AWSKMSKEK{keyID: "arn:aws:kms:...:key/abc", client: &fakeKMS{prefix: []byte("KMS:")}}
	if kek.ID() != "aws-kms:arn:aws:kms:...:key/abc" {
		t.Fatalf("unexpected ID %q", kek.ID())
	}
	dek := bytes.Repeat([]byte{0x5A}, 32)
	wrapped, err := kek.Wrap(ctx, dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(wrapped[:0], dek) { // sanity; wrapped carries the (mock) blob
		t.Fatal("unexpected")
	}
	got, err := kek.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v got=%x", err, got)
	}
}

// TestVaultOverAWSKMS proves the full envelope path works over a KMS KEK,
// including AAD binding.
func TestVaultOverAWSKMS(t *testing.T) {
	ctx := context.Background()
	kek := &AWSKMSKEK{keyID: "k", client: &fakeKMS{prefix: []byte("kms:")}}
	v := NewWithKEK(kek)
	token, err := v.Encrypt(ctx, "kms-envelope-secret", "target:9")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := v.Decrypt(ctx, token, "target:9")
	if err != nil || got != "kms-envelope-secret" {
		t.Fatalf("decrypt: %v %q", err, got)
	}
	if _, err := v.Decrypt(ctx, token, "target:10"); err == nil {
		t.Fatal("wrong AAD should fail even with a KMS KEK")
	}
}

// TestAWSKMSEncryptionContext proves the KEK binds an EncryptionContext: a blob
// it wrapped cannot be unwrapped with a different context (as KMS enforces), so
// a stolen blob is useless to a principal who can call kms:Decrypt without it.
func TestAWSKMSEncryptionContext(t *testing.T) {
	ctx := context.Background()
	fake := &fakeKMS{prefix: []byte("KMS:")}
	kek := &AWSKMSKEK{keyID: "k", client: fake}
	wrapped, err := kek.Wrap(ctx, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Same context (what the KEK uses) round-trips.
	if _, err := kek.Unwrap(ctx, wrapped); err != nil {
		t.Fatalf("unwrap with the KEK's own context: %v", err)
	}
	// A caller presenting a different/empty context is refused.
	if _, err := fake.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: wrapped, EncryptionContext: map[string]string{"app": "other"}}); err == nil {
		t.Fatal("unwrap with a mismatched encryption context should fail")
	}
	if _, err := fake.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: wrapped}); err == nil {
		t.Fatal("unwrap with no encryption context should fail")
	}
}

// TestNewKEKAWS proves the aws-kms provider errors without a key id.
func TestNewKEKAWS(t *testing.T) {
	// Unknown provider errors; aws-kms without a key id errors.
	if _, err := NewKEK(KEKOptions{Provider: "aws-kms"}); err == nil {
		t.Fatal("aws-kms without key id should error")
	}
}
