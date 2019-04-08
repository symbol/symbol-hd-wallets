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

### Generating mnemonic pass phrase

```typescript
// random 24-words mnemonic
const mnemonic = MnemonicPassPhrase.createRandom();

// random 12-words mnemonic
const mnemonic = MnemonicPassPhrase.createRandom('english', 128);

// random 24-words mnemonic with french wordlist
const mnemonic = MnemonicPassPhrase.createRandom('french');

// random 24-words mnemonic with japanese wordlist
const mnemonic = MnemonicPassPhrase.createRandom('japanese');
```

### Generating a hyper-deterministic wallet

```typescript
    TBD
```

## Changelog

Important versions listed below. Refer to the [Changelog](CHANGELOG.md) for a full history of the project.

- [0.1.0](CHANGELOG.md#v010) - 2019-03-08

## License

Licensed under the [BSD-2 License](LICENSE).
