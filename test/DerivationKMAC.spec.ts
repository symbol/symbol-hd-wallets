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
import {expect} from "chai";
import * as bip32 from 'bip32';
import {
    Account,
    NetworkType,
} from 'nem2-sdk';

// internal dependencies
import {
    ExtendedKey,
    KeyEncoding,
    MACType,
    Network,
} from "../index";

/**
 * BIP32-Ed25519 KMAC derivation Unit Tests
 *
 * Catapult HD Wallets *can* / *should* use KMAC instead
 * of HMAC for key derivation. This makes private keys
 * incompatible for SLIP-10.
 */
describe('BIP32-Ed15519 KMAC derivation -->', () => {

    const seed = '000102030405060708090a0b0c0d0e0f';
    const HMAC = {
        chainCode: '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb',
        masterPrv: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
        masterPub: '398d57dda0faae646097435e648a2c10f0f367b67e9a1e99a3d9170948d85750',
        neutered: [
            {path: 'm/0\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'b133c1d14999199ddefb03e815072f6fb14f1c22b201dab15f3373da8e26b17f',
             chain: '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'},
            {path: 'm/0\'/1\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'b4f591ac319f122425eaf5eb25f8d2b729d4009c59e56eebb54e697328f07fea',
             chain: 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'}
        ],
        nonNeutered: [
            {path: 'm/0\'', 
             key: '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3',
             chain: '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'},
            {path: 'm/0\'/1\'',
             key: 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2',
             chain: 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'}
        ]
    };

    const KMAC = {
        chainCode: '0589895ba87aa5d28d6e5d9d94f3323d22414ce3c91d5c63a223e1b045b0549f',
        masterPrv: '8297bf032455d6b42e544cbe3d4861a28c94a75071905c516a1a16ef17ecac5c',
        masterPub: 'aa16cb5de7b47df9eb805715d871c4ad9d346fa89b5874aa19a7765b681052dd',
        neutered: [
            {path: 'm/0\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '6d282315ad30a08184f01ec1fa3453f814155b151c09c31de4853ec69d47df40',
             chain: '1d615993bde463a451d6553f4deac7488a54062a0aebe09ecc35c3d01d47d08a'},
            {path: 'm/0\'/1\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '888b147936663c7eca406450f69951f190c7c4ca19dede9f5a8493843119c3ab',
             chain: 'a408fef3c6fd2aac83bbdd6b48eb865dc844793be117a90b86be215d2c163127'}
        ],
        nonNeutered: [
            {path: 'm/0\'', 
             key: 'fc58d8f1989084e76ea3c51acf7f5417f101b0c9b0f91afdb823c3fd2adda695',
             chain: '1d615993bde463a451d6553f4deac7488a54062a0aebe09ecc35c3d01d47d08a'},
            {path: 'm/0\'/1\'',
             key: 'b7eb9fdc76844c3950b8fde3094676193a33aa77aeb4a04cf204af7dd6dc120b',
             chain: 'a408fef3c6fd2aac83bbdd6b48eb865dc844793be117a90b86be215d2c163127'}
        ]
    };

    // create HMAC and KMAC master keys 
    const HMAC_masterKey = ExtendedKey.createFromSeed(
        seed,
        Network.CATAPULT
    );

    const KMAC_masterKey = ExtendedKey.createFromSeed(
        seed,
        Network.CATAPULT,
        MACType.KMAC
    );

    describe('ExtendedKey.createFromSeed() should', () => {
        it('use MACType.HMAC as default MAC type', () => {
            expect(HMAC_masterKey.macType).to.be.equal(MACType.HMAC);
        });

        it('permit specialization of macType property', () => {
            expect(KMAC_masterKey.macType).to.be.equal(MACType.KMAC);
        });
    });

    describe('Switching MAC type should', () => {
        it('define correct HMAC master private key', () => {
            expect(HMAC_masterKey.node.chainCode.toString('hex')).to.be.equal(HMAC.chainCode);
            expect(HMAC_masterKey.getPrivateKey()).to.be.equal(HMAC.masterPrv);
            expect(HMAC_masterKey.getPublicKey()).to.be.equal(HMAC.masterPub);
        });

        it('create different KMAC master private key', () => {
            expect(KMAC_masterKey.node.chainCode.toString('hex')).to.not.be.equal(HMAC.chainCode);
            expect(KMAC_masterKey.getPrivateKey()).to.not.be.equal(HMAC.masterPrv);
            expect(KMAC_masterKey.getPublicKey()).to.not.be.equal(HMAC.masterPub);
        });

        it('define correct KMAC master private key', () => {
            expect(KMAC_masterKey.node.chainCode.toString('hex')).to.be.equal(KMAC.chainCode);
            expect(KMAC_masterKey.getPrivateKey()).to.be.equal(KMAC.masterPrv);
            expect(KMAC_masterKey.getPublicKey()).to.be.equal(KMAC.masterPub);
        });

        it('derive correct HMAC extended public key given seed and path', () => {
            // iterate through paths to derive
            HMAC.neutered.map((neuteredKey) => {
                const childDerived = HMAC_masterKey.derivePath(neuteredKey.path);

                // test chain code of derived node
                expect(childDerived.node.chainCode.toString('hex')).to.be.equal(neuteredKey.chain);

                // test `getPublicKey()` and *neutered node* `getPublicKey()`
                expect(childDerived.getPublicKey()).to.be.equal(neuteredKey.key);
                expect(childDerived.getPublicNode().getPublicKey()).to.be.equal(neuteredKey.key);
            });
        });

        it('derive correct HMAC extended private key given seed and path', () => {
            // iterate through paths to derive
            HMAC.nonNeutered.map((nonNeuteredKey) => {
                const childDerived = HMAC_masterKey.derivePath(nonNeuteredKey.path);

                // test chain code of derived node
                expect(childDerived.node.chainCode.toString('hex')).to.be.equal(nonNeuteredKey.chain);

                // test `getPrivateKey()` return, SLIP-10-compliant
                expect(childDerived.getPrivateKey()).to.be.equal(nonNeuteredKey.key);
            });
        });

/// region KMAC key derivation
        it('derive correct KMAC extended public key given seed and path', () => {
            // iterate through paths to derive
            KMAC.neutered.map((neuteredKey) => {
                const childDerived = KMAC_masterKey.derivePath(neuteredKey.path);

                // test chain code of derived node
                expect(childDerived.node.chainCode.toString('hex')).to.be.equal(neuteredKey.chain);

                // test `getPublicKey()` and *neutered node* `getPublicKey()`
                expect(childDerived.getPublicKey()).to.be.equal(neuteredKey.key);
                expect(childDerived.getPublicNode().getPublicKey()).to.be.equal(neuteredKey.key);
            });
        });

        it('derive correct KMAC extended private key given seed and path', () => {
            // iterate through paths to derive
            KMAC.nonNeutered.map((nonNeuteredKey) => {
                const childDerived = KMAC_masterKey.derivePath(nonNeuteredKey.path);

                // test chain code of derived node
                expect(childDerived.node.chainCode.toString('hex')).to.be.equal(nonNeuteredKey.chain);

                // test `getPrivateKey()` return, SLIP-10-compliant
                expect(childDerived.getPrivateKey()).to.be.equal(nonNeuteredKey.key);
            });
        });
/// end-region KMAC key derivation

    });

});
