module github.com/celestiaorg/aws-kms-keyring

// Go 1.25.1: Utilizing latest language features and security patches
go 1.25.1

require (
	// Decentralized Identity support for MetaMask/Ethereum-style interactions
	github.com/MetaMask/go-did-it v1.0.0-pre1
	
	// AWS SDK v2: Modern, modular Go SDK for interacting with KMS and Config
	github.com/aws/aws-sdk-go-v2 v1.39.6
	github.com/aws/aws-sdk-go-v2/config v1.31.17
	github.com/aws/aws-sdk-go-v2/service/kms v1.34.0
	
	// Cosmos SDK: Core framework for Celestia and inter-blockchain communication
	github.com/cosmos/cosmos-sdk v0.51.6
	
	// Cryptography: Optimized secp256k1 curves used in Bitcoin and Ethereum
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
)

[Image of AWS Key Management Service (KMS) integration with Blockchain signing process]

/**
 * Key Management Architecture:
 * 1. AWS KMS: Holds the root entropy and performs signing in a protected environment.
 * 2. Keyring: Provides a standard interface for Cosmos-SDK to request signatures.
 * 3. Celestia: Uses this keyring for validator nodes or bridge nodes to secure accounts.
 */

// --- Critical Replace Directives (Forks & Fixes) ---
// These ensure Celestia-specific patches are applied over standard upstream versions.
replace (
	github.com/cometbft/cometbft => github.com/celestiaorg/celestia-core v0.39.13
	github.com/cosmos/cosmos-sdk => github.com/celestiaorg/cosmos-sdk v0.51.6
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
)

[Image of Hardware Security Module (HSM) vs Local Key Storage security levels]
