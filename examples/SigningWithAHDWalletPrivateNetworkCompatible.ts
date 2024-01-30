import symbolSdk from 'symbol-sdk';
import { Wallet } from '../src/Wallet';
import { ExtendedKey } from '../src/ExtendedKey';
import { Network } from '../src/Network';

const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.SYMBOL);
const wallet = new Wallet(xkey);

// derive specific child path
const childAccount = wallet.getChildAccountPrivateKey("m/44'/4343'/0'/0'/0'");

// create a transfer object
const facade = new symbolSdk.facade.SymbolFacade('testnet');

const transaction = facade.transactionFactory.create({
  type: 'transfer_transaction_v1',
  signerPublicKey: '87DA603E7BE5656C45692D5FC7F6D0EF8F24BB7A5C10ED5FDA8C5CFBC49FCBC8',
  fee: 1000000n,
  deadline: 41998024783n,
  recipientAddress: 'TCHBDENCLKEBILBPWP3JPB2XNY64OE7PYHHE32I',
  mosaics: [{ mosaicId: 0x7cdf3b117a3c40ccn, amount: 1000000n }],
});

// sign the transaction with derived account
const privateKey = new symbolSdk.PrivateKey(childAccount);
const signature = facade.signTransaction(new facade.constructor.KeyPair(privateKey), transaction);
const jsonPayload = facade.transactionFactory.constructor.attachSignature(transaction, signature);
