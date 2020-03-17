import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');
