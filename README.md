# AWS KMS Keyring

A reusable Go library that provides an AWS KMS-backed keyring implementation for Cosmos SDK applications. This library allows you to securely manage cryptographic keys using AWS Key Management Service (KMS) instead of storing them locally.

## Features

- **AWS KMS Integration**: Store and manage keys securely in AWS KMS
- **Cosmos SDK Compatible**: Implements the `keyring.Keyring` interface from cosmos-sdk
- **secp256k1 Support**: Full support for secp256k1 curve used by Celestia and other Cosmos chains
- **Pre-configured Aliases**: Uses manually created KMS aliases for maximum security and simplicity
- **Minimal Permissions**: Requires only `GetPublicKey` and `Sign` permissions
- **Automatic Caching**: Caches key metadata for improved performance
- **Parallel Worker Support**: Multiple aliases can be configured for parallel signing operations

## Installation

```bash
go get github.com/celestiaorg/aws-kms-keyring
```

## Usage

### Basic Setup

**Step 1: Create KMS keys manually**

First, create your keys in AWS KMS. You can use the AWS Console, AWS CLI, or CloudFormation:

```bash
# Using AWS CLI to create a secp256k1 key
aws kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY \
  --description "My Celestia key"

# Create an alias for the key
aws kms create-alias \
  --alias-name alias/myapp/key0 \
  --target-key-id <key-id-from-previous-command>
```

**Step 2: Configure and use the keyring**

```go
import (
    "context"
    awskeyring "github.com/celestiaorg/aws-kms-keyring"
)

// Configure the KMS keyring with pre-configured aliases
config := awskeyring.Config{
    Region: "us-west-2",
    Aliases: []string{
        "alias/myapp/key0",
    },
}

// Create the keyring
ctx := context.Background()
kr, err := awskeyring.NewKMSKeyring(ctx, "key0", config)
if err != nil {
    panic(err)
}

// Use the keyring with Cosmos SDK
// The keyring implements keyring.Keyring interface
// Access the key by its name (last part of the alias)
sig, pub, err := kr.Sign("key0", []byte("message"), signing.SignMode_SIGN_MODE_DIRECT)
```

### Multiple Keys for Parallel Workers

For applications with parallel workers that need to sign concurrently, pre-configure one alias per worker:

```bash
# Create keys for each worker
for i in 0 1 2; do
  KEY_ID=$(aws kms create-key \
    --key-spec ECC_SECG_P256K1 \
    --key-usage SIGN_VERIFY \
    --description "Worker $i key" \
    --query 'KeyMetadata.KeyId' \
    --output text)

  aws kms create-alias \
    --alias-name "alias/myapp/worker$i" \
    --target-key-id "$KEY_ID"
done
```

```go
config := awskeyring.Config{
    Region: "us-west-2",
    Aliases: []string{
        "alias/myapp/worker0",
        "alias/myapp/worker1",
        "alias/myapp/worker2",
    },
}

kr, err := awskeyring.NewKMSKeyring(ctx, "", config)

// Different workers can use different keys
kr.Sign("worker0", msg, signMode) // Worker 0
kr.Sign("worker1", msg, signMode) // Worker 1
kr.Sign("worker2", msg, signMode) // Worker 2

// Code that calls NewMnemonic() will also work
rec, _, err := kr.NewMnemonic("worker0", keyring.English, path, "", hd.Secp256k1)
// Returns the existing worker0 key
```

### Using with LocalStack for Testing

```go
config := awskeyring.Config{
    Region:      "us-east-1",
    Endpoint:    "http://localhost:4566", // LocalStack endpoint
    AliasPrefix: "alias/test/",
}
```

## Configuration

### Config Struct

```go
type Config struct {
    // Region is the AWS region for KMS (required)
    Region string

    // Endpoint is the KMS endpoint (optional, for testing with LocalStack)
    Endpoint string

    // Aliases is a list of pre-configured KMS alias names (required)
    // Each alias must already exist in KMS
    // Example: []string{"alias/myapp/key0", "alias/myapp/key1"}
    Aliases []string
}
```

**Important**: All aliases specified in the `Aliases` list must be created in AWS KMS before initializing the keyring. The keyring will expose these keys with UIDs based on the last part of the alias name (e.g., "alias/myapp/key0" becomes "key0").

## Keyring Operations

The library implements the full `keyring.Keyring` interface:

### Implementation Approach

This library implements the Cosmos SDK keyring interface with a **pre-configured alias** approach for maximum security and minimal permissions. Key implementation details:

- **Pre-configured Keys**: All KMS keys must be created manually by the user before using the keyring. This ensures full control over key lifecycle management.
- **Alias Mapping**: Key names in the keyring correspond to the last part of the KMS alias (e.g., `alias/myapp/key0` → `key0`).
- **Minimal Permissions**: Only requires `kms:GetPublicKey` and `kms:Sign` permissions - no destructive or administrative permissions needed.
- **No Dynamic Key Management**: The library intentionally does not create, import, or delete keys to maintain a simple security model.
- **KMS-First Design**: Operations that require exporting or manipulating private keys locally are intentionally unsupported, as they would defeat the purpose of using KMS for secure key management.

### Supported Operations

- ✅ `Backend()` - Returns "kms"
- ✅ `List()` - Lists all pre-configured keys
- ✅ `Key(uid)` - Gets a key by name
- ✅ `KeyByAddress(address)` - Gets a key by address
- ✅ `Sign(uid, msg, signMode)` - Signs a message with KMS
- ✅ `SignByAddress(address, msg, signMode)` - Signs by address
- ✅ `NewMnemonic(uid, ...)` - Returns a pre-configured key matching the UID (doesn't create new keys)
- ✅ `SupportedAlgorithms()` - Returns secp256k1

### Unsupported Operations

The following operations are not supported (will return error):
- ❌ `Delete()` / `DeleteByAddress()` - Keys must be managed through AWS KMS console/API
- ❌ `Rename()` - Aliases are immutable
- ❌ `NewAccount()` - Use `NewMnemonic()` instead (with pre-configured UIDs)
- ❌ `ImportPrivKeyHex()` - Keys must be pre-configured in KMS
- ❌ `ImportPrivKey()` - Keys must be pre-configured in KMS
- ❌ `SaveLedgerKey()` / `SaveOfflineKey()` / `SaveMultisig()` - Not applicable for KMS
- ❌ `ImportPubKey()` - Not applicable for KMS
- ❌ `ExportPubKeyArmor()` / `ExportPrivKeyArmor()` - KMS keys cannot be exported

### Important Note on `NewMnemonic()`

While `NewMnemonic()` is supported, it **does not create new keys**. Instead, it returns a pre-configured key that matches the requested UID. This provides compatibility with code that expects to create keys dynamically (like parallel worker pools) while maintaining the security model of pre-configured keys.

**Example**: If you configure aliases `["alias/app/worker0", "alias/app/worker1"]`, then calling `NewMnemonic("worker0", ...)` will return the existing "worker0" key.

## AWS IAM Permissions

This library requires minimal KMS permissions - only read and sign operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:GetPublicKey",
        "kms:Sign"
      ],
      "Resource": "*"
    }
  ]
}
```

For better security, you can restrict the `Resource` to specific key ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:GetPublicKey",
        "kms:Sign"
      ],
      "Resource": [
        "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        "arn:aws:kms:us-west-2:123456789012:key/abcdefab-abcd-abcd-abcd-abcdefabcdef"
      ]
    }
  ]
}
```

**Note**: Key creation and management should be handled separately with appropriate administrative permissions, not by the application using this keyring.

## Security Considerations

- **Key Storage**: Private keys never leave AWS KMS
- **Signing**: All signing operations are performed within KMS
- **Minimal Permissions**: Only requires `GetPublicKey` and `Sign` - no create, import, or delete permissions
- **Manual Key Management**: Keys are created and managed manually, providing full control over key lifecycle
- **Access Control**: Use AWS IAM policies to control access to specific keys
- **Audit**: All KMS operations are logged in AWS CloudTrail
- **Principle of Least Privilege**: The application cannot create or delete keys, reducing attack surface

## Testing

The library can be tested using [LocalStack](https://localstack.cloud/):

```bash
# Start LocalStack with KMS support
docker run -d -p 4566:4566 localstack/localstack

# Create test keys
aws --endpoint-url=http://localhost:4566 kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY

# Create alias (use the key-id from previous command)
aws --endpoint-url=http://localhost:4566 kms create-alias \
  --alias-name alias/test/key0 \
  --target-key-id <key-id>
```

```go
// Configure your test to use LocalStack endpoint
config := awskeyring.Config{
    Region:   "us-east-1",
    Endpoint: "http://localhost:4566",
    Aliases:  []string{"alias/test/key0"},
}

kr, err := awskeyring.NewKMSKeyring(ctx, "key0", config)
```

## Dependencies

- AWS SDK for Go v2
- Cosmos SDK (keyring interface)
- MetaMask go-did-it (secp256k1 key handling)
- Decred secp256k1 (signature parsing)

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [op-alt-da](https://github.com/celestiaorg/op-alt-da) - OP Stack alternative DA solution using Celestia
- [celestia-node](https://github.com/celestiaorg/celestia-node) - Celestia node implementation
