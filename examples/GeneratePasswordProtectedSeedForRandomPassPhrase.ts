import {MnemonicPassPhrase} from 'nem2-hd-wallets';

const mnemonic = MnemonicPassPhrase.createRandom();
const secureSeedHex = mnemonic.toSeed('your-password');
