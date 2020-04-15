// Example 2: empty password for password-protected seed
import {MnemonicPassPhrase} from 'symbol-hd-wallets';

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed(); // omit password means empty password: ''
