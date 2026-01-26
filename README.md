# AWS KMS Keyring

A minimal Go library that provides an AWS KMS-backed keyring implementation for Cosmos SDK applications. This library allows you to sign transactions using AWS Key Management Service (KMS) instead of storing keys locally.

## Features

- **AWS KMS Integration**: Sign transactions using keys stored in AWS KMS
- **Cosmos SDK Compatible**: Implements the `keyring.Keyring` interface
- **secp256k1 Support**: Full support for secp256k1 curve used by Celestia and other Cosmos chains
- **Minimal Permissions**: Only requires `kms:GetPublicKey` and `kms:Sign` permissions
- **Single Key Design**: Simple configuration with one pre-configured KMS key

## Installation

```bash
go get github.com/celestiaorg/aws-kms-keyring
```

## Usage

### Prerequisites

Create a secp256k1 key in AWS KMS:

```bash
# Create the key
KEY_ID=$(aws kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY \
  --query 'KeyMetadata.KeyId' \
  --output text)

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/my-celestia-key \
  --target-key-id "$KEY_ID"
```

### Basic Setup

```go
import (
    "context"
    awskeyring "github.com/celestiaorg/aws-kms-keyring"
)

// Configure the KMS keyring with a single key
config := awskeyring.Config{
    Region:  "us-west-2",
    KeyName: "alias/my-celestia-key",
}

// Create the keyring
ctx := context.Background()
kr, err := awskeyring.NewKMSKeyring(ctx, config)
if err != nil {
    panic(err)
}

// Use the keyring with Cosmos SDK
// The keyring implements keyring.Keyring interface
```

### Using with LocalStack for Testing

```go
config := awskeyring.Config{
    Region:   "us-east-1",
    Endpoint: "http://localhost:4566",
    KeyName:  "alias/test-key",
}
```

## Configuration

```go
type Config struct {
    // Region is the AWS region for KMS (required)
    Region string

    // Endpoint is the KMS endpoint (optional, for testing with LocalStack)
    Endpoint string

    // KeyName is the KMS key alias or key ID (required)
    // Examples: "alias/my-key", "1234abcd-12ab-34cd-56ef-1234567890ab"
    KeyName string
}
```

## Keyring Operations

### Supported Operations

| Operation | Description |
|-----------|-------------|
| `Backend()` | Returns "kms" |
| `List()` | Returns the single configured key |
| `Key(uid)` | Gets the key if uid matches KeyName |
| `KeyByAddress(address)` | Gets the key if address matches |
| `Sign(uid, msg, signMode)` | Signs a message using KMS |
| `SignByAddress(address, msg, signMode)` | Signs by address |
| `SupportedAlgorithms()` | Returns secp256k1 |

### Unsupported Operations

All key management operations return an error since keys must be pre-configured in KMS:

- `Delete()`, `DeleteByAddress()`, `Rename()`
- `NewMnemonic()`, `NewAccount()`
- `SaveLedgerKey()`, `SaveOfflineKey()`, `SaveMultisig()`
- `ImportPrivKey()`, `ImportPrivKeyHex()`, `ImportPubKey()`
- `ExportPubKeyArmor()`, `ExportPrivKeyArmor()`

## AWS IAM Permissions

Minimal permissions required:

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
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

## Testing

```bash
# Start LocalStack
docker run -d -p 4566:4566 localstack/localstack

# Create a test key
aws --endpoint-url=http://localhost:4566 kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY

# Run tests
go test ./...
```

## License

[MIT](LICENSE)

## Related Projects

- [op-alt-da](https://github.com/celestiaorg/op-alt-da) - OP Stack alternative DA solution using Celestia
