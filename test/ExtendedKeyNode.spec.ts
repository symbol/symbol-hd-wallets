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
import * as bip32 from 'bip32';

// internal dependencies
import {
    ExtendedKeyNode,
    KeyEncoding
} from "../index";

describe('ExtendedKeyNode -->', () => {

    const extendedKeys = {
        neutered: [
            {path: 'm', key: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'},
            {path: 'm/0', key: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'},
        ],
        nonNeutered: [
            {path: 'm', key: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'},
            {path: 'm/0', key: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'},
        ],
    }

    describe('constructor should', () => {
        it('create master key with payload for "m" path', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[0].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[0].key));

            expect(neuteredMaster.isMaster()).to.be.equal(true);
            expect(nonNeuteredMaster.isMaster()).to.be.equal(true);
        });

        it('create child key with payload for "m/0" path', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[1].key));

            expect(neuteredMaster.isMaster()).to.be.equal(false);
            expect(nonNeuteredMaster.isMaster()).to.be.equal(false);
        });

        it('create neutered from neutered keys', () => {
            extendedKeys.neutered.map(
                (neuteredKey) => {
                    const neuteredNode = new ExtendedKeyNode(bip32.fromBase58(neuteredKey.key));
                    expect(neuteredNode.isNeutered()).to.be.equal(true);
                });
        });

        it('create non-neutered from non-neutered keys', () => {
            extendedKeys.nonNeutered.map(
                (nonNeuteredKey) => {
                    const nonNeuteredNode = new ExtendedKeyNode(bip32.fromBase58(nonNeuteredKey.key));
                    expect(nonNeuteredNode.isNeutered()).to.be.equal(false);
                });
        });
    });

    describe('getPublicNode() should', () => {
        it('create neutered from non-neutered', () => {
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[0].key));
            const publicNode = nonNeuteredMaster.getPublicNode();

            expect(publicNode.isNeutered()).to.be.equal(true);
        });

        it('create neutered from neutered', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicNode = neuteredMaster.getPublicNode();

            expect(publicNode.isNeutered()).to.be.equal(true);
        });
    });

    describe('toBase58() should', () => {
        it('produce same payloads', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const neuteredBase58 = neuteredMaster.toBase58();
            const nonNeuteredBase58 = nonNeuteredMaster.toBase58();

            expect(neuteredBase58).to.be.equal(extendedKeys.neutered[1].key);
            expect(nonNeuteredBase58).to.be.equal(extendedKeys.nonNeutered[1].key);
        });
    });

    describe('getPrivateKey() should', () => {
        it('should throw error with neutered nodes', () => {
            expect((function () {
                const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
                const privateKey = neuteredMaster.getPrivateKey();
            })).to.throw('Cannot read private key out of extended public key.');
        });

        it('should return hexadecimal notation by default', () => {
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const privateKey = nonNeuteredMaster.getPrivateKey();

            expect(privateKey.length).to.be.equal(64);
            expect(privateKey).to.be.equal('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea');
        });

        it('should return binary notation with ENC_BIN', () => {
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const privateKey: Buffer = nonNeuteredMaster.getPrivateKey(KeyEncoding.ENC_BIN) as Buffer;
            const uintArray = new Uint8Array(privateKey);

            const expectedBytes = [
                237, 178, 225,  79,
                158, 231, 125,  38,
                221, 147, 180, 236,
                237, 232, 209, 110,
                212,   8, 206,  20,
                155, 108, 216,  11,
                  7,  21, 162, 217,
                 17, 160, 175, 234
            ]

            expect(privateKey).to.be.instanceof(Buffer);
            expect(privateKey.byteLength).to.be.equal(32);
            expect(uintArray.length).to.be.equal(32);
            expect(Array.from(uintArray)).to.be.deep.equal(expectedBytes);
        });
    });

    describe('getPublicKey() should', () => {
        it('should return public key for both neutered and non-neutered', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[0].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[0].key));
            const neuteredPubKey = neuteredMaster.getPublicKey();
            const nonNeuteredPubKey = nonNeuteredMaster.getPublicKey();

            expect(neuteredPubKey.length).to.be.equal(64);
            expect(nonNeuteredPubKey.length).to.be.equal(64);
        });

        it('should return hexadecimal notation by default', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicKey = neuteredMaster.getPublicKey();

            expect(publicKey.length).to.be.equal(64);
            expect(publicKey).to.be.equal('5a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56');
        });

        it('should return binary notation with ENC_BIN', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicKey: Buffer = neuteredMaster.getPublicKey(KeyEncoding.ENC_BIN) as Buffer;
            const uintArray = new Uint8Array(publicKey);

            const expectedBytes = [
                 90, 120,  70,  98,
                164, 162,  10, 101,
                191, 106, 171, 154,
                233, 138, 108,   6,
                138, 129, 197,  46,
                 75,   3,  44,  15,
                181,  64,  12, 112,
                108, 252, 204,  86
            ];

            expect(publicKey).to.be.instanceof(Buffer);
            expect(publicKey.byteLength).to.be.equal(32);
            expect(uintArray.length).to.be.equal(32);
            expect(Array.from(uintArray)).to.be.deep.equal(expectedBytes);
        });
    });

});
