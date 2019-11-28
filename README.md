# nem2-hd-wallets

[![npm version](https://badge.fury.io/js/nem2-hd-wallets.svg)](https://badge.fury.io/js/nem2-hd-wallets)
[![Build Status](https://travis-ci.org/nemfoundation/nem2-hd-wallets.svg?branch=master)](https://travis-ci.org/nemfoundation/nem2-hd-wallets)
[![Slack](https://img.shields.io/badge/chat-on%20slack-green.svg)](https://nem2.slack.com/messages/CB0UU89GS//)

*The author of this package cannot be held responsible for any loss of money or any malintentioned usage forms of this package. Please use this package with caution.*

NEM HD Wallets generator to generate hyper-deterministic wallets for the Catapult (NEM2) platform.

This is a PoC to validate the proposed [NIP6 Multi-Account Hierarchy for Deterministic Wallets](https://github.com/nemtech/NIP/issues/12). When stable, the repository will be moved to the [nemtech](https://github.com/nemtech) organization.

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

// create mnemonic from 24 known words
const words = 'alpha pattern real admit vacuum wall ready code '
            + 'correct program depend valid focus basket whisper firm '
            + 'tray fit rally day dance demise engine mango';
const mnemonic = new MnemonicPassPhrase(words);

// another way to create mnemonic is from Entropy(seed Hex string). providing a language is also optional
const mnemonic = MnemonicPassPhrase.createFromEntropy('07142acb81df09ed6cb16830957cebf865a2267ea2bae7aafac51c037474929c','english')
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

### Generating an extended key from a mnemonic pass phrase

```typescript
import {MnemonicPassPhrase, ExtendedKey} from 'nem2-hd-wallets';

// using BIP39 mnemonic pass phrase for BIP32 extended keys generation
const mnemonic = MnemonicPassPhrase.createRandom();

// Example 1: create extended key from mnemonic seed (network parameter is optional)
const bip32Seed = mnemonic.toSeed(); // using empty password
const hexSeed = bip32Seed.toString('hex')
const xkey = ExtendedKey.createFromSeed(hexSeed, Network.CATAPULT);

// Example 2: create extended key from hex Entropy
const hexEntropy = mnemonic.toEntropy(); // using empty password
const xkey = ExtendedKey.createFromEntropy(hexEntropy, Network.CATAPULT);
```

### Generating a hyper-deterministic wallet (CATAPULT **mijin** and **mijinTest** compatible)

```typescript
const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.MIJIN_TEST);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.MIJIN_TEST);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();
```

### Generating a hyper-deterministic wallet (CATAPULT **public** and **publicTest** compatible)

```typescript
const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT_PUBLIC);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.TEST_NET);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();
```

### Signing with a hyper-deterministic wallet (CATAPULT compatible)

```typescript
const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT_PUBLIC);
const wallet = new Wallet(xkey);

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// create a transfer object
const transfer = TransferTransaction.create(/*...*/);

// sign the transaction with derived account
const signedTx = childAccount.sign(transfer, generationHash);
```

## License

Licensed under the [BSD-2 License](LICENSE).
