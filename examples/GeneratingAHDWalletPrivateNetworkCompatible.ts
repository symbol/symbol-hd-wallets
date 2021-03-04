import {NetworkType} from 'symbol-sdk';
import {ExtendedKey} from "../src/ExtendedKey";
import {Wallet} from "../src/Wallet";
import {Network} from "../src/Network";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.MIJIN);
const wallet = new Wallet(xkey);

// get master account
const masterAccount = wallet.getAccount();

// get DEFAULT ACCOUNT
const defaultAccount = wallet.getChildAccount();

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/4343\'/0\'/0\'/0\'', NetworkType.MIJIN_TEST);

// get read-only wallet
const readOnlyWallet = new Wallet(xkey.getPublicNode());
const readOnlyAccount = readOnlyWallet.getPublicAccount(NetworkType.MIJIN_TEST);

// get read-only DEFAULT ACCOUNT
const readOnlyDefaultAccount = readOnlyWallet.getChildPublicAccount();
