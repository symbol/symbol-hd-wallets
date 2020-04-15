import {MnemonicPassPhrase} from 'symbol-hd-wallets';

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');
