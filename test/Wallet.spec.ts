/**
 * Copyright 2019 NEM
 *
 * Licensed under the BSD 2-Clause License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-2-Clause
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
import {expect} from 'chai';
import {Account, NetworkType, PublicAccount,} from 'symbol-sdk';
// internal dependencies
import {ExtendedKey, Network, Wallet,} from '../index';
import { MnemonicPassPhrase } from '../src/MnemonicPassPhrase';

import {testVectors} from './data/test-hd-derivation-data';

const networkType = NetworkType.MIJIN_TEST;

function getChildAccount(wallet: Wallet, path: string = Wallet.DEFAULT_WALLET_PATH) {
    return Account.createFromPrivateKey(wallet.getChildAccountPrivateKey(path), networkType)
}

function getAccount(wallet: Wallet) {
    return Account.createFromPrivateKey(wallet.getAccountPrivateKey(), networkType)
}

function getPublicAccount(wallet: Wallet) {
    return PublicAccount.createFromPublicKey(wallet.getAccountPublicKey(), networkType)
}

function getChildPublicAccount(wallet: Wallet, path: string = Wallet.DEFAULT_WALLET_PATH) {
    return PublicAccount.createFromPublicKey(wallet.getChildAccountPublicKey(path), networkType)
}

function buildAccountPath(pathArr: number[]) {
    return `m/${pathArr[0]}\'/${pathArr[1]}\'/${pathArr[2]}\'/${pathArr[3]}\'/${pathArr[4]}\'`
}

describe('Wallet -->', () => {

    const masterSeed = '000102030405060708090a0b0c0d0e0f';
    const chainCode  = '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb';

    // m
    const masterPriv = '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7';
    const masterPub  = 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed';

    // m/44'/4343'/0'/0'/0'
    const defaultPriv = 'bb2724a538cfd64e4366feb36bb982b954d58ea78f7163451b3b514edd692159';
    const defaultPub = '36f81b855a4bf5ab675867ac4d2705d4304a09c0a79a63d734dde0926ab27eee';

    // m/44'/4343'/1'/0'/0'
    const secondPriv = '8c91d9f5d214a2e80a275e75a165f7022712f7ad52b7ecd45b3b6cc76154b571';
    const secondPub = 'ecba28a413d60d37387eb19dd881b1e9ca4e2aba0f759fde735ce8969e129347';

    describe('constructor should', () => {

        it('take extended key and set read-only to false when non-neutered', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);

            expect(wallet.isReadOnly()).to.be.equal(false);
        });

        it('take extended key and set read-only to true when neutered', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect(wallet.isReadOnly()).to.be.equal(true);
        });

        it('take extended key to create wallet and get correct private key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getAccount(wallet);

            expect(account.privateKey.toLowerCase()).to.be.equal(masterPriv);
        });
    });

    describe('getAccount() should', () => {

        it('throw when wallet initialized with extended public key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect(() => {
                getAccount(wallet);
            }).to.throw('Missing private key, please use method getAccountPublicKey().');
        });

        it('get catapult compatible private key / public key pair (keypair)', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getAccount(wallet);

            expect(account.privateKey.toLowerCase()).to.be.equal(masterPriv);
            expect(account.publicKey.toLowerCase()).to.be.equal(masterPub);
        });
    });

    describe('getChildAccount() should', () => {

        it('throw when wallet initialized with extended public key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect(() => {
                getChildAccount(wallet);
            }).to.throw('Missing private key, please use method getChildAccountPublicKey().');
        });

        it('derive default account when given no path', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getChildAccount(wallet);

            expect(account.privateKey.toLowerCase()).to.be.equal(defaultPriv);
            expect(account.publicKey.toLowerCase()).to.be.equal(defaultPub);
        });

        it('derive second account when given path m/44\'/4343\'/1\'/0\'/0\'', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getChildAccount(wallet, 'm/44\'/4343\'/1\'/0\'/0\'');

            expect(account.privateKey.toLowerCase()).to.be.equal(secondPriv);
            expect(account.publicKey.toLowerCase()).to.be.equal(secondPub);
        });
    });

    describe('getPublicAccount() should', () => {

        it('get catapult compatible read-only account given extended private key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getPublicAccount(wallet);

            expect(account).to.be.instanceof(PublicAccount);
            expect(account.publicKey.toLowerCase()).to.be.equal(masterPub);
        });

        it('get catapult compatible read-only account given extended public key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);
            const account = getPublicAccount(wallet);

            expect(account).to.be.instanceof(PublicAccount);
            expect(account.publicKey.toLowerCase()).to.be.equal(masterPub);
        });
    });

    describe('getChildPublicAccount() should', () => {

        it('derive default account when given no path', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getChildPublicAccount(wallet);

            expect(account).to.be.instanceof(PublicAccount);
            expect(account.publicKey.toLowerCase()).to.be.equal(defaultPub);
        });

        it('derive second account when given path m/44\'/4343\'/1\'/0\'/0\'', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.SYMBOL);
            const wallet = new Wallet(xkey);
            const account = getChildPublicAccount(wallet, 'm/44\'/4343\'/1\'/0\'/0\'');

            expect(account).to.be.instanceof(PublicAccount);
            expect(account.publicKey.toLowerCase()).to.be.equal(secondPub);
        });
    });


    describe('hd derivation test data', () => {
        const vectors = [...testVectors.public_net, ...testVectors.test_net];
        it('should run with mnemonic successfully', () => {
            vectors.filter(v => v.mnemonic !== undefined).forEach((vector) => {
                const mnemonic = new MnemonicPassPhrase(vector.mnemonic!!)
                const seedHex = mnemonic.toSeed(vector.passphrase!!).toString('hex').toLowerCase();
                expect(seedHex).to.be.equal(vector.seed.toLowerCase());
                // create hd extended key
                const extendedKey = ExtendedKey.createFromSeed(seedHex, Network.SYMBOL);
                const wallet = new Wallet(extendedKey);
                expect(wallet.getAccountPublicKey().toLowerCase()).to.be.eq(vector.rootPublicKey.toLowerCase());
                vector.childAccounts.forEach(child => {
                    const childAccount = getChildPublicAccount(wallet, buildAccountPath(child.path))
                    expect(childAccount.publicKey.toLowerCase()).to.be.eq(child.publicKey.toLowerCase());
                })
            })
        }).timeout(15000)

        it('should run pass with seed successfully', () => {
            vectors.filter(v => v.mnemonic === undefined).forEach((vector) => {
                const seedHex = vector.seed.toLowerCase()
                // create hd extended key
                const extendedKey = ExtendedKey.createFromSeed(seedHex, Network.SYMBOL);
                const wallet = new Wallet(extendedKey);
                expect(wallet.getAccountPublicKey().toLowerCase()).to.be.eq(vector.rootPublicKey.toLowerCase());
                vector.childAccounts.forEach(child => {
                    const childAccount = getChildPublicAccount(wallet, buildAccountPath(child.path))
                    expect(childAccount.publicKey.toLowerCase()).to.be.eq(child.publicKey.toLowerCase());
                })
            })
        }).timeout(15000)


    })
});
