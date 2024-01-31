import { ExtendedKey } from '../src/ExtendedKey';
import { Wallet } from '../src/Wallet';
import { Network } from '../src/Network';

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.SYMBOL);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccountPrivateKey();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccountPrivateKey();

// derive specific child path
const childAccount = wallet.getChildAccountPrivateKey("m/44'/4343'/0'/0'/0'");

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getAccountPublicKey();

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildAccountPublicKey();
