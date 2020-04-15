import {ExtendedKey, Network, Wallet} from 'symbol-hd-wallets';
import {NetworkType} from 'symbol-sdk';

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT_PUBLIC);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.TEST_NET);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();
