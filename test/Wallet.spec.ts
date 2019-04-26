/**
 * Copyright 2019 Grégory Saive for NEM Foundation
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
import {expect} from "chai";
import {
    NetworkType,
} from 'nem2-sdk';

// internal dependencies
import {
    CurveAlgorithm,
    ExtendedKey,
    KeyEncoding,
    Network,
    NodeInterface,
    NodeEd25519,
    Wallet,
} from "../index";

describe('Wallet -->', () => {

    const masterSeed = '000102030405060708090a0b0c0d0e0f';
    const masterPriv = '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7';
    const masterPub  = '398d57dda0faae646097435e648a2c10f0f367b67e9a1e99a3d9170948d85750';
    const chainCode  = '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb';

    describe('constructor should', () => {

        it('take extended key and set read-only to false when non-neutered', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const wallet = new Wallet(xkey);

            expect(wallet.isReadOnly()).to.be.equal(false);
        });

        it('take extended key and set read-only to true when neutered', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect(wallet.isReadOnly()).to.be.equal(true);
        });

        it('take extended key to create wallet and get correct private key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const wallet = new Wallet(xkey);
            const account = wallet.getAccount();

            expect(account.privateKey.toLowerCase()).to.be.equal(masterPriv);
        });
    });

    describe('getAccount() should', () => {

        it('throw when wallet initialized with extended public key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect((function () {
                wallet.getAccount();
            })).to.throw('Missing private key, please use method getPublicAccount().');
        });

        it('get catapult compatible private key / public key pair (keypair)', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const wallet = new Wallet(xkey);
            const account = wallet.getAccount();

            expect(account.privateKey.toLowerCase()).to.be.equal(masterPriv);
            expect(account.publicKey.toLowerCase()).to.be.equal(masterPub);
        });
    });

    describe('getChildAccount() should', () => {

        it('throw when wallet initialized with extended public key', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);

            expect((function () {
                wallet.getChildAccount();
            })).to.throw('Missing private key, please use method getChildPublicAccount().');
        });

        it('get catapult compatible public key read-only account', () => {
            const xkey = ExtendedKey.createFromSeed(masterSeed, Network.CATAPULT);
            const xpub = xkey.getPublicNode();
            const wallet = new Wallet(xpub);
            const account = wallet.getPublicAccount();

            expect(account.publicKey.toLowerCase()).to.be.equal(masterPub);
        });
    });
});
