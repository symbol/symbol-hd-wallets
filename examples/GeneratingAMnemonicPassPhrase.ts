import {MnemonicPassPhrase} from 'nem2-hd-wallets';

// random 24-words mnemonic
MnemonicPassPhrase.createRandom();

// random 12-words mnemonic
MnemonicPassPhrase.createRandom('english', 128);

// random 24-words mnemonic with french wordlist
MnemonicPassPhrase.createRandom('french');

// random 24-words mnemonic with japanese wordlist
MnemonicPassPhrase.createRandom('japanese');
