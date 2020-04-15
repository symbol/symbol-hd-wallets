import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 1: generate BIP32 master seed for random pass phrase
const mnemonic = MnemonicPassPhrase.createRandom();
const bip32Seed = mnemonic.toSeed();
