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

```ts
// examples/GeneratingAMnemonicPassPhrase.ts

import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// random 24-words mnemonic
MnemonicPassPhrase.createRandom();

// random 12-words mnemonic
MnemonicPassPhrase.createRandom('english', 128);

// random 24-words mnemonic with french wordlist
MnemonicPassPhrase.createRandom('french');

// random 24-words mnemonic with japanese wordlist
MnemonicPassPhrase.createRandom('japanese');

```

### Generating a password-protected mnemonic pass phrase seed (for storage)

```ts
// examples/GeneratePasswordProtectedSeedForRandomPassPhrase.ts

import {MnemonicPassPhrase} from 'nem2-hd-wallets';

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');

```

```ts
// examples/GeneratePasswordProtectedSeedForRandomPassPhraseEmptyPassword.ts

// Example 2: empty password for password-protected seed
import {MnemonicPassPhrase} from 'nem2-hd-wallets';

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed(); // omit password means empty password: ''

```

### Generating a root (master) extended key

```ts
// examples/GeneratingARootMasterExtendedKeyForKnownPassPhrase.ts

import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// Example 2: generate BIP32 master seed for known pass phrase
const words = 'alpha pattern real admit vacuum wall ready code '
    + 'correct program depend valid focus basket whisper firm '
    + 'tray fit rally day dance demise engine mango';
const mnemonic = new MnemonicPassPhrase(words);

// the following seed can be used with `ExtendedKey.createFromSeed()`
const bip32Seed = mnemonic.toSeed(); // using empty password

```

```ts
// examples/GeneratingARootMasterExtendedKeyForRandomPassPhrase.ts

import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// Example 1: generate BIP32 master seed for random pass phrase
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toSeed();

```

### Generating a hyper-deterministic wallet (CATAPULT **mijin** and **mijinTest** compatible)

```ts
// examples/GeneratingAHDWalletPrivateNetworkCompatible.ts

import {ExtendedKey, Network, Wallet} from 'nem2-hd-wallets';
import {NetworkType} from 'nem2-sdk';

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

```ts
// examples/GeneratingAHDWalletPublicNetworkCompatible.ts

import {ExtendedKey, Network, Wallet} from 'nem2-hd-wallets';
import {NetworkType} from 'nem2-sdk';

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

```ts
// examples/SigningWithAHDWalletPrivateNetworkCompatible.ts

import {ExtendedKey, Network, Wallet} from 'nem2-hd-wallets';
import {Account, Deadline, EmptyMessage, NetworkType, TransferTransaction} from "nem2-sdk";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT_PUBLIC);
const wallet = new Wallet(xkey);

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// create a transfer object
const transfer = TransferTransaction.create(
    Deadline.create(),
    Account.generateNewAccount(NetworkType.TEST_NET).address,
    [],
    EmptyMessage,
    NetworkType.TEST_NET);

// sign the transaction with derived account
const generationHash = ''; // replace with network generation hash
const signedTx = childAccount.sign(transfer, generationHash);

```
## License

Licensed under the [BSD-2 License](LICENSE).
