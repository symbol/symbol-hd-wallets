# CHANGELOG

# v0.8.0

- upgrade upstream nem2-sdk@v0.17.0
- dropped KECCAK/SHA3 key derivation for SHA512
- added compatibility with SLIP-10 key derivation
- dropped SHA3/KECCAK derivation dependent on Network sign schema
- dropped usage of SignSchema
- dropped class CatapultECC in favor of `tweetnacl`

# v0.7.0

- upgraded upstream nem2-sdk@v0.16.0

# v0.6.1

- added embedme examples embedded in readme
- upgraded upstream nem2-sdk@v0.15.0

# v0.6.0

- updated dependency tree

## v0.5.5

- fixed readme samples

## v0.5.4

- updated nem2-sdk dependency to 0.15.0
- updated other dependencies including bip44-constants

## v0.5.3

- added unit tests for Network class (BIP32 "network")
- added unit tests for inconsistent network usage
- added Error `Inconsistent networkType.` given non-matching network and catapult network type

## v0.5.2

- fixed `CKDPriv()` implementation to forward `network` property
- added unit tests for Trezor key generation compatibility
- now passes unit tests for SHA3 and Keccak hash algorithm for derivations
- fixed `README.md` to hold correct `toSeed();` usage
- updated nem2-sdk dependency and other packages

## v0.5.1

- fixed Trezor compatibility for public key generation
- added unit tests for keccak reversed private keys (NIS compatibility mode)

## v0.5.0

- added Network.CATAPULT_PUBLIC to work with public networks
- fixed Catapult private/public networks key compatibility
- fixed `CatapultECC` implementation to resolve sign schema
- fixed `NodeEd25519` to permit SHA3 and Keccak public key generation
- added unit tests for nemtech/test-vectors compatibility

## v0.4.0

- implement KMAC authentication codes for key derivation
- added HMAC as default key derivation scheme
- added class MACImpl responsible for MAC generation
- added enum MACType with HMAC and KMAC
- added ExtendedKey.macType and ExtendedKey.DEFAULT_MAC_TYPE

## v0.3.1

- added tests for getAccount, getChildAccount
- added tests for getPublicAccount, getChildPublicAccount
- fixed typos and documentation

## v0.3.0

- added `Wallet` draft implementation
- refactor `ExtendedKeyNode` to `ExtendedKey`
- remove `NodeImpl` template class

## v0.2.0

- added draft implementation for `DeterministicKey` abstraction compatibility layer
- added draft implementation for `NodeEd25519` with `derivePath()` and `CKDPriv`
- added utility class `Cryptography`
- added Catapult elliptic curve cryptography helpers `CatapultECC``
- added BIP32 compatible `NodeInterface` interface
- added kernel layer `ExtendedKeyNode` implementation compatible with `BIP32` and `NodeEd25519` deterministic keys
- added client layer `ExtendedKey` currently initializable only with Base58 keys
- added draft implementation of BIP32-compatible multi-curve implementation with `NodeImpl` variadic template

## v0.1.0

- added draft implementation for `MnemonicPassPhrase`
- added first BIP39 mnemonic pass phrase generation features
