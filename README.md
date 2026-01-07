# AWS KMS Keyring

A reusable Go library that provides an AWS KMS-backed keyring implementation for Cosmos SDK applications. This library allows you to securely manage cryptographic keys using AWS Key Management Service (KMS) instead of storing them locally.

## Features

- **AWS KMS Integration**: Store and manage keys securely in AWS KMS
- **Cosmos SDK Compatible**: Implements the `keyring.Keyring` interface from cosmos-sdk
- **secp256k1 Support**: Full support for secp256k1 curve used by Celestia and other Cosmos chains
- **Key Import**: Import existing private keys (hex-encoded) into KMS
- **Key Generation**: Create new keys directly in KMS
- **Alias Management**: Uses KMS aliases for human-readable key names
- **Automatic Caching**: Caches key metadata for improved performance

## Installation

```bash
go get github.com/celestiaorg/aws-kms-keyring
```

## Usage

### Basic Setup

```go
import (
    "context"
    awskeyring "github.com/celestiaorg/aws-kms-keyring"
)

// Configure the KMS keyring
config := awskeyring.Config{
    Region:      "us-west-2",
    AliasPrefix: "alias/myapp/",
}

// Create the keyring
ctx := context.Background()
kr, err := awskeyring.NewKMSKeyring(ctx, "default-key", config)
if err != nil {
    panic(err)
}

// Use the keyring with Cosmos SDK
// The keyring implements keyring.Keyring interface
```

### Import Existing Key

```go
config := awskeyring.Config{
    Region:        "us-west-2",
    AliasPrefix:   "alias/myapp/",
    ImportKeyName: "my-key",
    ImportKeyHex:  "1234567890abcdef...", // Your hex-encoded private key
}

kr, err := awskeyring.NewKMSKeyring(ctx, "my-key", config)
// The key will be imported into KMS on initialization (idempotent)
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

    // AliasPrefix is the prefix for KMS key aliases (default: "alias/op-alt-da/")
    AliasPrefix string

    // ImportKeyName is the name of the key to import (optional)
    ImportKeyName string

    // ImportKeyHex is the hex-encoded private key to import (optional)
    ImportKeyHex string
}
```

## Keyring Operations

The library implements the full `keyring.Keyring` interface:

### Supported Operations

- ✅ `Backend()` - Returns "kms"
- ✅ `List()` - Lists all keys
- ✅ `Key(uid)` - Gets a key by name
- ✅ `KeyByAddress(address)` - Gets a key by address
- ✅ `Sign(uid, msg, signMode)` - Signs a message with KMS
- ✅ `SignByAddress(address, msg, signMode)` - Signs by address
- ✅ `NewMnemonic(...)` - Creates a new key in KMS
- ✅ `ImportPrivKeyHex(...)` - Imports a hex-encoded private key
- ✅ `SupportedAlgorithms()` - Returns secp256k1

### Unsupported Operations

The following operations are not supported (will return error):
- ❌ `Delete()` - Keys should be managed through AWS KMS console
- ❌ `DeleteByAddress()` - Keys should be managed through AWS KMS console
- ❌ `Rename()` - Aliases are immutable
- ❌ `NewAccount()` - Use `NewMnemonic()` instead
- ❌ `SaveLedgerKey()` - Not applicable for KMS
- ❌ `SaveOfflineKey()` - Not applicable for KMS
- ❌ `SaveMultisig()` - Not applicable for KMS
- ❌ `ImportPrivKey()` - Use `ImportPrivKeyHex()` instead
- ❌ `ImportPubKey()` - Not applicable for KMS
- ❌ `ExportPubKeyArmor()` - Not applicable for KMS
- ❌ `ExportPrivKeyArmor()` - KMS keys cannot be exported

## AWS IAM Permissions

Your AWS credentials need the following KMS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:ListAliases",
        "kms:DescribeKey",
        "kms:GetParametersForImport",
        "kms:ImportKeyMaterial"
      ],
      "Resource": "*"
    }
  ]
}
```

## Security Considerations

- **Key Storage**: Private keys never leave AWS KMS
- **Signing**: All signing operations are performed within KMS
- **Key Import**: Imported keys are wrapped using RSA-OAEP before transmission to KMS
- **Access Control**: Use AWS IAM policies to control access to keys
- **Audit**: All KMS operations are logged in AWS CloudTrail

## Testing

The library can be tested using [LocalStack](https://localstack.cloud/):

```bash
# Start LocalStack with KMS support
docker run -d -p 4566:4566 localstack/localstack

# Configure your test to use LocalStack endpoint
config := awskeyring.Config{
    Region:   "us-east-1",
    Endpoint: "http://localhost:4566",
}
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
