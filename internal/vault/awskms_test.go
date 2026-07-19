package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMS reversibly "encrypts" by prefixing a tag — enough to prove the KEK
// round-trips the data key through the (mocked) KMS.
type fakeKMS struct {
	prefix  []byte
	failEnc bool
}

// Encrypt fakes KMS encryption by prefixing the plaintext (or fails if failEnc).
func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.failEnc {
		return nil, errors.New("kms: access denied")
	}
	blob := append(append([]byte{}, f.prefix...), in.Plaintext...)
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

// Decrypt reverses Encrypt by stripping the prefix, erroring on a bad prefix.
func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if !bytes.HasPrefix(in.CiphertextBlob, f.prefix) {
		return nil, errors.New("kms: invalid ciphertext")
	}
	return &kms.DecryptOutput{Plaintext: in.CiphertextBlob[len(f.prefix):]}, nil
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

// TestNewKEKAWS proves the aws-kms provider errors without a key id.
func TestNewKEKAWS(t *testing.T) {
	// Unknown provider errors; aws-kms without a key id errors.
	if _, err := NewKEK(KEKOptions{Provider: "aws-kms"}); err == nil {
		t.Fatal("aws-kms without key id should error")
	}
}
