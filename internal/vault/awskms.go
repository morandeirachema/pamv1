package vault

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// kmsAPI is the slice of the AWS KMS client the KEK uses (so tests inject a fake).
type kmsAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AWSKMSKEK wraps data keys with AWS KMS: KMS encrypts/decrypts the 32-byte data
// key directly (well under the 4KB limit), so the KMS customer master key never
// leaves KMS. Production, vendor-aligned; uses the standard AWS credential chain.
type AWSKMSKEK struct {
	keyID  string
	client kmsAPI
}

func NewAWSKMSKEK(ctx context.Context, region, keyID string) (*AWSKMSKEK, error) {
	if keyID == "" {
		return nil, errors.New("vault: aws-kms KEK requires PAM_KEK_AWS_KEY_ID")
	}
	var opts []func(*awscfg.LoadOptions) error
	if region != "" {
		opts = append(opts, awscfg.WithRegion(region))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &AWSKMSKEK{keyID: keyID, client: kms.NewFromConfig(cfg)}, nil
}

func (k *AWSKMSKEK) ID() string { return "aws-kms:" + k.keyID }

func (k *AWSKMSKEK) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	out, err := k.client.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(k.keyID), Plaintext: dek})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

func (k *AWSKMSKEK) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	out, err := k.client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(k.keyID), CiphertextBlob: wrapped})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
