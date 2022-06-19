package seacrypt

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func DecryptSecrets(ctx context.Context, kmsClient *kms.Client, kmsKeyId string, cipherTextBase64 string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", err
	}

	output, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(kmsKeyId),
		CiphertextBlob:      bytes,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return "", err
	}
	return string(output.Plaintext), nil
}

func GetKmsClient(ctx context.Context) (*kms.Client, error) {
	awsConfig, err := getAwsCredentials(ctx)
	if err != nil {
		return nil, err
	}
	kmsClient := kms.NewFromConfig(*awsConfig)
	return kmsClient, nil
}

func getAwsCredentials(ctx context.Context) (*aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
