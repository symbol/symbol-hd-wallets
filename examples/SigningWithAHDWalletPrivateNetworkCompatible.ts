import {ExtendedKey, Network, Wallet} from 'symbol-hd-wallets';
import {Account, Deadline, EmptyMessage, NetworkType, TransferTransaction} from "symbol-sdk";

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.CATAPULT_PUBLIC);
const wallet = new Wallet(xkey);

// derive specific child path
const childAccount = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'', NetworkType.TEST_NET);

// create a transfer object
const transfer = TransferTransaction.create(
    Deadline.create(),
    Account.generateNewAccount(NetworkType.TEST_NET).address,
    [],
    EmptyMessage,
    NetworkType.TEST_NET);

// sign the transaction with derived account
const generationHash = ''; // replace with network generation hash
const signedTx = childAccount.sign(transfer, generationHash);
