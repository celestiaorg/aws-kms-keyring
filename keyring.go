package awskeyring

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

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

var (
	errUnsupportedKMSOp = errors.New("kms keyring: operation not supported")
)

// Config configures an AWS KMS-backed keyring using pre-configured aliases.
// Users must manually create KMS keys and aliases before using this keyring.
// This design minimizes required permissions (only GetPublicKey and Sign).
type Config struct {
	Region   string
	Endpoint string

	// Aliases is a list of pre-configured KMS alias names (e.g., "alias/op-alt-da/key0").
	// Each alias must already exist in KMS. The keyring will expose these as keys
	// with UIDs based on the alias name (e.g., "key0" for "alias/op-alt-da/key0").
	// For parallel workers, provide multiple aliases and each worker can use a different one.
	Aliases []string
}

type kmsKeyring struct {
	ctx    context.Context
	client *kms.Client
	config Config

	mu         sync.RWMutex
	records    map[string]*kmsCachedRecord
	addrLookup map[string]string
}

type kmsCachedRecord struct {
	keyID string
	rec   *keyring.Record
	pub   cryptotypes.PubKey
}


// NewKMSKeyring creates a new AWS KMS-backed keyring using pre-configured aliases.
// The provided context is used for KMS operations.
// All aliases specified in cfg.Aliases must already exist in KMS.
// If defaultKey is specified, it will validate that the key exists in the configured aliases.
func NewKMSKeyring(ctx context.Context, defaultKey string, cfg Config) (keyring.Keyring, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("kms region is required")
	}
	if len(cfg.Aliases) == 0 {
		return nil, fmt.Errorf("at least one alias must be configured")
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	// Create KMS client with optional custom endpoint
	var kmsClient *kms.Client
	if cfg.Endpoint != "" {
		kmsClient = kms.NewFromConfig(awsCfg, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	} else {
		kmsClient = kms.NewFromConfig(awsCfg)
	}

	k := &kmsKeyring{
		ctx:        ctx,
		client:     kmsClient,
		config:     cfg,
		records:    make(map[string]*kmsCachedRecord),
		addrLookup: make(map[string]string),
	}

	// Load all pre-configured aliases
	if err := k.initCache(); err != nil {
		return nil, err
	}

	// Validate default key existence if specified
	if defaultKey != "" {
		if _, err := k.getRecord(defaultKey); err != nil {
			return nil, fmt.Errorf("kms key %q not found: %w", defaultKey, err)
		}
	}

	return k, nil
}

// initCache loads all pre-configured aliases into the cache.
// Each alias is queried to get its public key and build a keyring record.
func (k *kmsKeyring) initCache() error {
	newRecords := make(map[string]*kmsCachedRecord)
	newAddrIndex := make(map[string]string)

	for _, aliasName := range k.config.Aliases {
		// Extract key name from alias (remove the alias prefix if present)
		// Example: "alias/op-alt-da/key0" -> "key0"
		keyName := aliasName
		if idx := strings.LastIndex(aliasName, "/"); idx != -1 {
			keyName = aliasName[idx+1:]
		}

		cached, err := k.buildRecord(keyName, aliasName)
		if err != nil {
			return fmt.Errorf("build record for alias %s: %w", aliasName, err)
		}

		addr := sdk.AccAddress(cached.pub.Address()).String()
		newRecords[keyName] = cached
		newAddrIndex[addr] = keyName
	}

	k.mu.Lock()
	k.records = newRecords
	k.addrLookup = newAddrIndex
	k.mu.Unlock()

	return nil
}

// buildRecord creates a keyring record for a KMS key identified by alias or key ID.
// The keyIdentifier can be either an alias name (e.g., "alias/op-alt-da/key0") or a key ID.
func (k *kmsKeyring) buildRecord(name, keyIdentifier string) (*kmsCachedRecord, error) {
	pkResp, err := k.client.GetPublicKey(k.ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyIdentifier)})
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	pubKey, err := kmsPubKeyToCosmos(pkResp.PublicKey)
	if err != nil {
		return nil, err
	}

	anyPub, err := types.NewAnyWithValue(pubKey)
	if err != nil {
		return nil, fmt.Errorf("pack pubkey: %w", err)
	}

	rec := &keyring.Record{
		Name:   name,
		PubKey: anyPub,
		Item: &keyring.Record_Offline_{
			Offline: &keyring.Record_Offline{},
		},
	}

	// Store the actual key ID from the response for signing operations
	actualKeyID := aws.ToString(pkResp.KeyId)
	return &kmsCachedRecord{keyID: actualKeyID, rec: rec, pub: pubKey}, nil
}

func kmsPubKeyToCosmos(derBytes []byte) (cryptotypes.PubKey, error) {
	pub, err := secp256k1x509.PublicKeyFromX509DER(derBytes)
	if err != nil {
		return nil, err
	}

	// ToBytes() returns 33-byte compressed format
	return &secp256k1.PubKey{Key: pub.ToBytes()}, nil
}

func (k *kmsKeyring) Backend() string {
	return "kms"
}

func (k *kmsKeyring) List() ([]*keyring.Record, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := make([]*keyring.Record, 0, len(k.records))
	names := make([]string, 0, len(k.records))
	for name := range k.records {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		records = append(records, k.records[name].rec)
	}
	return records, nil
}

func (k *kmsKeyring) SupportedAlgorithms() (keyring.SigningAlgoList, keyring.SigningAlgoList) {
	algos := keyring.SigningAlgoList{hd.Secp256k1}
	return algos, algos
}

func (k *kmsKeyring) Key(uid string) (*keyring.Record, error) {
	cached, err := k.getRecord(uid)
	if err != nil {
		return nil, err
	}
	return cached.rec, nil
}

func (k *kmsKeyring) KeyByAddress(address sdk.Address) (*keyring.Record, error) {
	k.mu.RLock()
	name, ok := k.addrLookup[address.String()]
	k.mu.RUnlock()
	if !ok {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return k.Key(name)
}

// getRecord retrieves a key record from the cache.
// Keys must be pre-configured in the Config.Aliases list.
func (k *kmsKeyring) getRecord(name string) (*kmsCachedRecord, error) {
	k.mu.RLock()
	cached, ok := k.records[name]
	k.mu.RUnlock()
	if !ok {
		return nil, sdkerrors.ErrKeyNotFound
	}
	return cached, nil
}

func (k *kmsKeyring) Delete(string) error               { return errUnsupportedKMSOp }
func (k *kmsKeyring) DeleteByAddress(sdk.Address) error { return errUnsupportedKMSOp }
func (k *kmsKeyring) Rename(string, string) error       { return errUnsupportedKMSOp }

// NewMnemonic returns a pre-configured key that matches the requested UID.
// Since AWS KMS doesn't support mnemonic-based HD wallets, this method doesn't actually
// create a new key. Instead, it returns an existing pre-configured key if the UID matches.
// This allows compatibility with code that expects to "create" keys dynamically.
//
// For parallel workers, ensure you pre-configure enough aliases (e.g., "alias/app/key0",
// "alias/app/key1", etc.) and call NewMnemonic with matching UIDs ("key0", "key1", etc.).
func (k *kmsKeyring) NewMnemonic(uid string, _ keyring.Language, _, _ string, algo keyring.SignatureAlgo) (*keyring.Record, string, error) {
	// Validate algorithm
	if algo != hd.Secp256k1 {
		return nil, "", fmt.Errorf("kms: only secp256k1 supported, got %s", algo)
	}

	// Check if the requested key exists in pre-configured aliases
	cached, err := k.getRecord(uid)
	if err != nil {
		return nil, "", fmt.Errorf("kms: key %q not found in pre-configured aliases - ensure KMS alias exists and is configured in Config.Aliases: %w", uid, err)
	}

	// Return the existing key (no mnemonic since KMS doesn't use them)
	return cached.rec, "", nil
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

func (k *kmsKeyring) Sign(uid string, msg []byte, _ signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	cached, err := k.getRecord(uid)
	if err != nil {
		return nil, nil, err
	}

	sigResp, err := k.client.Sign(k.ctx, &kms.SignInput{
		KeyId:            aws.String(cached.keyID),
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

	return signature, cached.pub, nil
}

func (k *kmsKeyring) SignByAddress(address sdk.Address, msg []byte, signMode signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	k.mu.RLock()
	name, ok := k.addrLookup[address.String()]
	k.mu.RUnlock()
	if !ok {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}
	return k.Sign(name, msg, signMode)
}

// derSignatureToSecp converts a DER-encoded ECDSA signature from AWS KMS to raw secp256k1 format (64 bytes: R || S).
// It uses github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa for robust parsing and automatic low-S normalization.
func derSignatureToSecp(der []byte) ([]byte, error) {
	// Parse DER signature using the battle-tested decred library
	sig, err := secp256k1ecdsa.ParseDERSignature(der)
	if err != nil {
		return nil, fmt.Errorf("parse der signature: %w", err)
	}

	// Extract R and S values
	r := sig.R()
	s := sig.S()

	// Normalize S to low-S form (BIP 62) if needed
	// This is required for Cosmos signature verification
	if s.IsOverHalfOrder() {
		s = *new(dcrsecp256k1.ModNScalar).NegateVal(&s)
	}

	// Convert to 32-byte arrays
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Concatenate R and S to create the 64-byte signature format expected by Cosmos
	result := make([]byte, 64)
	copy(result[:32], rBytes[:])
	copy(result[32:], sBytes[:])

	return result, nil
}

func (k *kmsKeyring) ImportPrivKey(_ string, _ string, _ string) error {
	return fmt.Errorf("kms: armored import not supported, use ImportPrivKeyHex for hex-encoded keys")
}

func (k *kmsKeyring) ImportPrivKeyHex(uid string, privKeyHex string, algoStr string) error {
	return fmt.Errorf("kms: key import not supported - all keys must be pre-configured in KMS")
}
func (k *kmsKeyring) ImportPubKey(string, string) error        { return errUnsupportedKMSOp }
func (k *kmsKeyring) ExportPubKeyArmor(string) (string, error) { return "", errUnsupportedKMSOp }
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
