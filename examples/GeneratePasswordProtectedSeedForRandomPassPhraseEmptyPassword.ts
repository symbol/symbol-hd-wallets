import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 2: empty password for password-protected seed
const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed(); // omit password means empty password: ''
