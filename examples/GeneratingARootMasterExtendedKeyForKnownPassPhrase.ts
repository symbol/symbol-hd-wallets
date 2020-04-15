import {MnemonicPassPhrase} from "../src/MnemonicPassPhrase";

// Example 2: generate BIP32 master seed for known pass phrase
const words = 'alpha pattern real admit vacuum wall ready code '
    + 'correct program depend valid focus basket whisper firm '
    + 'tray fit rally day dance demise engine mango';
const mnemonic = new MnemonicPassPhrase(words);

// the following seed can be used with `ExtendedKey.createFromSeed()`
const bip32Seed = mnemonic.toSeed(); // using empty password
