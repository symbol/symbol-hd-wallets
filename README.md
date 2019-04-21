# nem2-hd-wallets

[![npm version](https://badge.fury.io/js/nem2-hd-wallets.svg)](https://badge.fury.io/js/nem2-hd-wallets)
[![Build Status](https://travis-ci.org/evias/nem2-hd-wallets.svg?branch=master)](https://travis-ci.org/evias/nem2-hd-wallets)
[![Slack](https://img.shields.io/badge/chat-on%20slack-green.svg)](https://nem2.slack.com/messages/CB0UU89GS//)

:warning: **This package is currently still in development, please do not use in production.** *The author of this package cannot be held responsible for any loss of money or any malintentioned usage forms of this package. Please use this package with caution.*

NEM HD Wallets generator to generate hyper-deterministic wallets for the Catapult (NEM2) platform.

This is a PoC to validate the proposed [NIP? Multi-Account Hierarchy for Deterministic Wallets](https://github.com/nemtech/NIP/issues/12). When stable, the repository will be moved to the [nemtech](https://github.com/nemtech) organization.

## Installation

`npm install nem2-hd-wallets`

## Examples

### Generating a mnemonic pass phrase

```typescript
import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// random 24-words mnemonic
const mnemonic = MnemonicPassPhrase.createRandom();

// random 12-words mnemonic
const mnemonic = MnemonicPassPhrase.createRandom('english', 128);

// random 24-words mnemonic with french wordlist
const mnemonic = MnemonicPassPhrase.createRandom('french');

// random 24-words mnemonic with japanese wordlist
const mnemonic = MnemonicPassPhrase.createRandom('japanese');
```

### Generating a password-protected mnemonic pass phrase seed (for storage)

```typescript
import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// Example 1: generate password-protected seed for random pass phrase
const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');

// Example 2: empty password for password-protected seed
const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed(); // omit password means empty password: ''
```

### Generating a BIP32 root extended key

```typescript
import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// Example 1: generate BIP32 master seed for random pass phrase
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();

// Example 2: generate BIP32 master seed for known pass phrase
const words = 'alpha pattern real admit vacuum wall ready code '
            + 'correct program depend valid focus basket whisper firm '
            + 'tray fit rally day dance demise engine mango';
const mnemonic = new MnemonicPassPhrase(words);

 // the following seed can be used with `ExtendedKeyNode.createFromSeed()`
const bip32Seed = mnemonic.toEntropy();
```

### Generating a BIP32 extended _private_ key from BIP39 mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKeyNode} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();
const bip32Node = ExtendedKeyNode.createFromSeed(bip32Seed);

// the extended private key (never share, base of private keys tree)
const xprvKey = bip32Node.toBase58();
```

### Generating a BIP32 extended _public_ key from BIP39 mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKeyNode} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();
const bip32Node = ExtendedKeyNode.createFromSeed(bip32Seed);

// the extended public key (base of public keys tree)
const xpubKey = bip32Node.getPublicNode().toBase58();
```

### Derive BIP44 path of a BIP32 extended key with BIP44 mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKeyNode} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();
const bip32Node = ExtendedKeyNode.createFromSeed(bip32Seed);

// derive BIP44 tree root
const bip44Root = bip32Node.derivePath("m/44'");

// the extended private key (never share, base of private keys tree)
const xprvKey = bip32Node.toBase58();

// the extended public key (never share, base of private keys tree)
const xpubKey = bip32Node.getPublicNode().toBase58();
```

### Derive default wallet BIP44 from a BIP39 mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKeyNode} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();
const bip32Node = ExtendedKeyNode.createFromSeed(bip32Seed);

// derive default wallet path "m/44'/43'/0'/0/0"
const defaultWallet = bip32Node.derivePath("m/44'/43'/0'/0/0");

// the extended private key (never share, base of private keys tree)
const xprvKey = defaultWallet.toBase58();

// the extended public key (default wallet base of public keys tree)
const xpubKey = defaultWallet.getPublicNode().toBase58();
```

### Derive second account with BIP44 from a BIP39 mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKeyNode} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toEntropy();
const bip32Node = ExtendedKeyNode.createFromSeed(bip32Seed);

// derive default wallet path "m/44'/43'/1'/0/0"
const defaultWallet = bip32Node.derivePath("m/44'/43'/1'/0/0"); // second hardened account

// the extended private key (never share, base of private keys tree)
const xprvKey = defaultWallet.toBase58();

// the extended public key (default wallet base of public keys tree)
const xpubKey = defaultWallet.getPublicNode().toBase58();
```

### Generating a hyper-deterministic wallet (CATAPULT compatible)

```typescript
    TBD
```

### Signing with a hyper-deterministic wallet (CATAPULT compatible)

```typescript
    TBD
```

## Changelog

Important versions listed below. Refer to the [Changelog](CHANGELOG.md) for a full history of the project.

- [0.2.0](CHANGELOG.md#v020) - 2019-04-20
- [0.1.0](CHANGELOG.md#v010) - 2019-03-08

## License

Licensed under the [BSD-2 License](LICENSE).
