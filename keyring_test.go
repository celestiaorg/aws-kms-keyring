package awskeyring

import (
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	secp256k1x509 "github.com/MetaMask/go-did-it/crypto/secp256k1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
)

type mockKMSClient struct {
	privKey   *dcrsecp256k1.PrivateKey
	pubKeyDER []byte
	keyID     string
}

func newMockKMSClient(t *testing.T) *mockKMSClient {
	privKey, err := dcrsecp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Create secp256k1 public key wrapper and encode to DER
	secpPub, err := secp256k1x509.PublicKeyFromXY(pubKey.X().Bytes()[:], pubKey.Y().Bytes()[:])
	require.NoError(t, err)
	derBytes := secpPub.ToX509DER()

	return &mockKMSClient{
		privKey:   privKey,
		pubKeyDER: derBytes,
		keyID:     "mock-key-id-12345",
	}
}

func (m *mockKMSClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		KeyId:     aws.String(m.keyID),
		PublicKey: m.pubKeyDER,
	}, nil
}

func (m *mockKMSClient) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	hash := sha256.Sum256(input.Message)
	sig := secp256k1ecdsa.SignCompact(m.privKey, hash[:], false)
	// SignCompact returns [v, r, s], we need DER format
	// Extract r and s (each 32 bytes, skip first byte which is recovery flag)
	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:65])

	// Create DER signature manually
	derSig := encodeDER(r, s)

	return &kms.SignOutput{
		Signature:        derSig,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}, nil
}

func encodeDER(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Add leading zero if high bit is set (to ensure positive integer)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0}, sBytes...)
	}

	// DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
	totalLen := 2 + len(rBytes) + 2 + len(sBytes)
	der := make([]byte, 0, 2+totalLen)
	der = append(der, 0x30, byte(totalLen))
	der = append(der, 0x02, byte(len(rBytes)))
	der = append(der, rBytes...)
	der = append(der, 0x02, byte(len(sBytes)))
	der = append(der, sBytes...)
	return der
}

type testKeyring struct {
	*kmsKeyring
	mock *mockKMSClient
}

func newTestKeyring(t *testing.T, keyName string) *testKeyring {
	mock := newMockKMSClient(t)

	k := &kmsKeyring{
		ctx: context.Background(),
		config: Config{
			Region:  "us-east-1",
			KeyName: keyName,
		},
	}

	// Manually load key using mock
	output, err := mock.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: aws.String(keyName),
	})
	require.NoError(t, err)

	pubKey, err := kmsPubKeyToCosmos(output.PublicKey)
	require.NoError(t, err)

	anyPub, err := codecNewAnyWithValue(pubKey)
	require.NoError(t, err)

	k.keyID = aws.ToString(output.KeyId)
	k.pubKey = pubKey
	k.addr = sdk.AccAddress(pubKey.Address()).String()
	k.record = &keyring.Record{
		Name:   keyName,
		PubKey: anyPub,
		Item:   &keyring.Record_Offline_{Offline: &keyring.Record_Offline{}},
	}

	return &testKeyring{kmsKeyring: k, mock: mock}
}

func codecNewAnyWithValue(pubKey cryptotypes.PubKey) (*types.Any, error) {
	return types.NewAnyWithValue(pubKey)
}

// Sign override to use mock client
func (tk *testKeyring) Sign(uid string, msg []byte, mode signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if uid != tk.config.KeyName {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}

	sigResp, err := tk.mock.Sign(tk.ctx, &kms.SignInput{
		KeyId:            aws.String(tk.keyID),
		Message:          msg,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, nil, err
	}

	signature, err := derSignatureToSecp(sigResp.Signature)
	if err != nil {
		return nil, nil, err
	}

	return signature, tk.pubKey, nil
}

func (tk *testKeyring) SignByAddress(address sdk.Address, msg []byte, signMode signing.SignMode) ([]byte, cryptotypes.PubKey, error) {
	if address.String() != tk.addr {
		return nil, nil, sdkerrors.ErrKeyNotFound
	}
	return tk.Sign(tk.config.KeyName, msg, signMode)
}

func TestBackend(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")
	require.Equal(t, "kms", kr.Backend())
}

func TestList(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")
	records, err := kr.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, "alias/test-key", records[0].Name)
}

func TestKey(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")

	rec, err := kr.Key("alias/test-key")
	require.NoError(t, err)
	require.Equal(t, "alias/test-key", rec.Name)

	_, err = kr.Key("nonexistent")
	require.Error(t, err)
}

func TestKeyByAddress(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")

	addr := sdk.AccAddress(kr.pubKey.Address())
	rec, err := kr.KeyByAddress(addr)
	require.NoError(t, err)
	require.Equal(t, "alias/test-key", rec.Name)

	wrongAddr := sdk.AccAddress([]byte("wrong-address"))
	_, err = kr.KeyByAddress(wrongAddr)
	require.Error(t, err)
}

func TestSign(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")

	msg := []byte("test message to sign")
	sig, pubKey, err := kr.Sign("alias/test-key", msg, signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	require.Len(t, sig, 64)
	require.NotNil(t, pubKey)

	// Verify wrong key name fails
	_, _, err = kr.Sign("wrong-key", msg, signing.SignMode_SIGN_MODE_DIRECT)
	require.Error(t, err)
}

func TestSignByAddress(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")

	msg := []byte("test message")
	addr := sdk.AccAddress(kr.pubKey.Address())

	sig, pubKey, err := kr.SignByAddress(addr, msg, signing.SignMode_SIGN_MODE_DIRECT)
	require.NoError(t, err)
	require.Len(t, sig, 64)
	require.NotNil(t, pubKey)

	wrongAddr := sdk.AccAddress([]byte("wrong"))
	_, _, err = kr.SignByAddress(wrongAddr, msg, signing.SignMode_SIGN_MODE_DIRECT)
	require.Error(t, err)
}

func TestUnsupportedOperations(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")

	require.ErrorIs(t, kr.Delete("key"), errUnsupportedKMSOp)
	require.ErrorIs(t, kr.Rename("old", "new"), errUnsupportedKMSOp)

	_, _, err := kr.NewMnemonic("uid", keyring.English, "", "", nil)
	require.ErrorIs(t, err, errUnsupportedKMSOp)

	_, err = kr.NewAccount("", "", "", "", nil)
	require.ErrorIs(t, err, errUnsupportedKMSOp)

	require.ErrorIs(t, kr.ImportPrivKey("", "", ""), errUnsupportedKMSOp)
	require.ErrorIs(t, kr.ImportPubKey("", ""), errUnsupportedKMSOp)

	_, err = kr.ExportPubKeyArmor("")
	require.ErrorIs(t, err, errUnsupportedKMSOp)

	_, err = kr.ExportPrivKeyArmor("", "")
	require.ErrorIs(t, err, errUnsupportedKMSOp)
}

func TestDerSignatureToSecp(t *testing.T) {
	// Create a known DER signature and verify conversion
	r := new(big.Int).SetBytes(make([]byte, 32))
	r.SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	s := new(big.Int).SetBytes(make([]byte, 32))
	s.SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	der := encodeDER(r, s)
	result, err := derSignatureToSecp(der)
	require.NoError(t, err)
	require.Len(t, result, 64)
}

func TestSupportedAlgorithms(t *testing.T) {
	kr := newTestKeyring(t, "alias/test-key")
	supported, ledger := kr.SupportedAlgorithms()
	require.Len(t, supported, 1)
	require.Len(t, ledger, 1)
}
