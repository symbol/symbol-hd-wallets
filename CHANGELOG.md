# CHANGELOG

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
