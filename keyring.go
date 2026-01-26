package awskeyring

import (
	"context"
	"errors"
	"fmt"

	secp256k1x509 "github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var errUnsupportedKMSOp = errors.New("kms keyring: operation not supported")

// Config configures an AWS KMS-backed keyring with a single key.
type Config struct {
	Region   string
	Endpoint string
	KeyName  string // The KMS key alias (e.g., "alias/my-key")
}

type kmsKeyring struct {
	ctx    context.Context
	client *kms.Client
	config Config

	keyID  string
	record *keyring.Record
	pubKey cryptotypes.PubKey
	addr   string
}

// NewKMSKeyring creates a new AWS KMS-backed keyring with a single configured key.
func NewKMSKeyring(ctx context.Context, cfg Config) (keyring.Keyring, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("kms region is required")
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("kms key name is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var kmsClient *kms.Client
	if cfg.Endpoint != "" {
		kmsClient = kms.NewFromConfig(awsCfg, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	} else {
		kmsClient = kms.NewFromConfig(awsCfg)
	}

	k := &kmsKeyring{
		ctx:    ctx,
		client: kmsClient,
		config: cfg,
	}

	if err := k.loadKey(); err != nil {
		return nil, err
	}

	return k, nil
}

func (k *kmsKeyring) loadKey() error {
	pkResp, err := k.client.GetPublicKey(k.ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(k.config.KeyName),
	})
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	pubKey, err := kmsPubKeyToCosmos(pkResp.PublicKey)
	if err != nil {
		return err
	}

	anyPub, err := types.NewAnyWithValue(pubKey)
	if err != nil {
		return fmt.Errorf("pack pubkey: %w", err)
	}

	k.keyID = aws.ToString(pkResp.KeyId)
	k.pubKey = pubKey
	k.addr = sdk.AccAddress(pubKey.Address()).String()
	k.record = &keyring.Record{
		Name:   k.config.KeyName,
		PubKey: anyPub,
		Item:   &keyring.Record_Offline_{Offline: &keyring.Record_Offline{}},
	}

	return nil
}

func kmsPubKeyToCosmos(derBytes []byte) (cryptotypes.PubKey, error) {
	pub, err := secp256k1x509.PublicKeyFromX509DER(derBytes)
	if err != nil {
		return nil, err
	}
	return &secp256k1.PubKey{Key: pub.ToBytes()}, nil
}

func (k *kmsKeyring) Backend() string { return "kms" }

func (k *kmsKeyring) List() ([]*keyring.Record, error) {
	return []*keyring.Record{k.record}, nil
}

func (k *kmsKeyring) SupportedAlgorithms() (keyring.SigningAlgoList, keyring.SigningAlgoList) {
	algos := keyring.SigningAlgoList{hd.Secp256k1}
	return algos, algos
}

func (k *kmsKeyring) Key(uid string) (*keyring.Record, error) {
	if uid != k.config.KeyName {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return k.record, nil
}

func (k *kmsKeyring) KeyByAddress(address sdk.Address) (*keyring.Record, error) {
	if address.String() != k.addr {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return k.record, nil
}

func (k *kmsKeyring) Sign(uid string, msg []byte, _ signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if uid != k.config.KeyName {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}

	sigResp, err := k.client.Sign(k.ctx, &kms.SignInput{
		KeyId:            aws.String(k.keyID),
		Message:          msg,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("kms sign: %w", err)
	}

	signature, err := derSignatureToSecp(sigResp.Signature)
	if err != nil {
		return nil, nil, err
	}

	return signature, k.pubKey, nil
}

func (k *kmsKeyring) SignByAddress(address sdk.Address, msg []byte, signMode signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if address.String() != k.addr {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}
	return k.Sign(k.config.KeyName, msg, signMode)
}

func derSignatureToSecp(der []byte) ([]byte, error) {
	sig, err := secp256k1ecdsa.ParseDERSignature(der)
	if err != nil {
		return nil, fmt.Errorf("parse der signature: %w", err)
	}

	r := sig.R()
	s := sig.S()

	if s.IsOverHalfOrder() {
		s = *new(dcrsecp256k1.ModNScalar).NegateVal(&s)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	result := make([]byte, 64)
	copy(result[:32], rBytes[:])
	copy(result[32:], sBytes[:])

	return result, nil
}

// Unsupported operations
func (k *kmsKeyring) Delete(string) error               { return errUnsupportedKMSOp }
func (k *kmsKeyring) DeleteByAddress(sdk.Address) error { return errUnsupportedKMSOp }
func (k *kmsKeyring) Rename(string, string) error       { return errUnsupportedKMSOp }
func (k *kmsKeyring) NewMnemonic(string, keyring.Language, string, string, keyring.SignatureAlgo) (*keyring.Record, string, error) {
	return nil, "", errUnsupportedKMSOp
}
func (k *kmsKeyring) NewAccount(string, string, string, string, keyring.SignatureAlgo) (*keyring.Record, error) {
	return nil, errUnsupportedKMSOp
}
func (k *kmsKeyring) SaveLedgerKey(string, keyring.SignatureAlgo, string, uint32, uint32, uint32) (*keyring.Record, error) {
	return nil, errUnsupportedKMSOp
}
func (k *kmsKeyring) SaveOfflineKey(string, cryptotypes.PubKey) (*keyring.Record, error) {
	return nil, errUnsupportedKMSOp
}
func (k *kmsKeyring) SaveMultisig(string, cryptotypes.PubKey) (*keyring.Record, error) {
	return nil, errUnsupportedKMSOp
}
func (k *kmsKeyring) ImportPrivKey(string, string, string) error    { return errUnsupportedKMSOp }
func (k *kmsKeyring) ImportPrivKeyHex(string, string, string) error { return errUnsupportedKMSOp }
func (k *kmsKeyring) ImportPubKey(string, string) error             { return errUnsupportedKMSOp }
func (k *kmsKeyring) ExportPubKeyArmor(string) (string, error)      { return "", errUnsupportedKMSOp }
func (k *kmsKeyring) ExportPubKeyArmorByAddress(sdk.Address) (string, error) {
	return "", errUnsupportedKMSOp
}
func (k *kmsKeyring) ExportPrivKeyArmor(string, string) (string, error) {
	return "", errUnsupportedKMSOp
}
func (k *kmsKeyring) ExportPrivKeyArmorByAddress(sdk.Address, string) (string, error) {
	return "", errUnsupportedKMSOp
}
func (k *kmsKeyring) MigrateAll() ([]*keyring.Record, error) { return nil, errUnsupportedKMSOp }
