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
import {
    Account,
    NetworkType,
} from 'nem2-sdk';

// internal dependencies
import {
    ExtendedKeyNode,
    KeyEncoding,
    Network,
} from "../index";
import { ExtendedKey } from "../src/ExtendedKey";

/**
 * BIP32-Ed25519 Extended Keys Unit Tests
 * 
 * Catapult neutered nodes are different from SLIP-10 because of
 * SHA3-256 usage. Extended Private Keys (nonNeutered nodes) are
 * copied from SLIP-10 but Public Keys in SLIP-10 are generated
 * with SHA512 while for Catapult we use SHA3-256.
 *
 * @see BIP32 Test Vectors: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
 * @see Test vector 1: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519 
 * @see Test vector 2: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519 
 */
describe('BIP32-Ed15519 Extended Keys -->', () => {

    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    const extendedKeys = [
    // Test vector 1: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    // Catapult neutered nodes are different from SLIP-10 because of SHA3-256 usage.
    // Extended Private Keys (nonNeutered nodes) are copied from SLIP-10 but Public Keys
    // in SLIP-10 are generated with SHA512 while for Catapult we use SHA3-256
    {
        label: 'Vector #1',
        seedHex: '000102030405060708090a0b0c0d0e0f',
        chainCode: '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb',
        masterPub: 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed',
        masterPrv: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
        catapultPub: '398d57dda0faae646097435e648a2c10f0f367b67e9a1e99a3d9170948d85750',
        // Catapult neutered nodes are different from SLIP-10 because of SHA3-256 usage.
        neutered: [
            {path: 'm/0\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'b133c1d14999199ddefb03e815072f6fb14f1c22b201dab15f3373da8e26b17f',
             chain: '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'},
            {path: 'm/0\'/1\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'b4f591ac319f122425eaf5eb25f8d2b729d4009c59e56eebb54e697328f07fea',
             chain: 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'},
            {path: 'm/0\'/1\'/2\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'e51e8260001a2788cbf3e9dd89d21cef34080670c2b182236f85ee48cdabfec1',
             chain: '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c'},
            {path: 'm/0\'/1\'/2\'/2\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '3a14558899d4ebcc220afff7012f690e9f625006686b4eef3f1d7125e3e87222',
             chain: '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc'},
            {path: 'm/0\'/1\'/2\'/2\'/1000000000\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'c53618757b76cc34376b7464902b18e495651c69f47cd2e7a2910d401fba2f94',
             chain: '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230'},
        ],
        nonNeutered: [
            {path: 'm/0\'', 
             key: '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3',
             chain: '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'},
            {path: 'm/0\'/1\'',
             key: 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2',
             chain: 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'},
            {path: 'm/0\'/1\'/2\'',
             key: '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9',
             chain: '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c'},
            {path: 'm/0\'/1\'/2\'/2\'',
             key: '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662',
             chain: '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc'},
            {path: 'm/0\'/1\'/2\'/2\'/1000000000\'',
             key: '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793',
             chain: '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230'},
        ],
    },
    // Test vector 2: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    {
        label: 'Vector #2',
        seedHex: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        chainCode: 'ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b',
        masterPub: '8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a',
        masterPrv: '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012',
        catapultPub: '8d806491b531735af494d211d801cc87c0c66703634a016cd1e3dd188b4ca1e6',
        neutered: [
            {path: 'm/0\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '5e2d0e53f031fc783a664ab03a7e0c6e980e87c515b968590eff09eb34de6db3',
             chain: '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d'},
            {path: 'm/0\'/2147483647\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '4fd948675902bf11678bda28ba3faec9798bedfd8c8d702652d5a5e6ea73c8b2',
             chain: '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f'},
            {path: 'm/0\'/2147483647\'/1\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: '8a326dd01e22229d043434140982b1f538332ae4e745b15f0b359501c2b9bb9a',
             chain: '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'd774ca736001d91d8048e102702ffe32b306d43103dfb54df7d3869a0d1cc3b7',
             chain: '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'/2\'',
             // Ed25519-compliant SHA3-256 instead of SHA512!! (different from SLIP-10)
             key: 'f3fd8f892731eda80e8c21f2b4167ea8b9b59bda85101f8595f78041cde1d303',
             chain: '5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4'},
        ],
        nonNeutered: [
            {path: 'm/0\'',
             key: '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635',
             chain: '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d'},
            {path: 'm/0\'/2147483647\'',
             key: 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4',
             chain: '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f'},
            {path: 'm/0\'/2147483647\'/1\'',
             key: '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c',
             chain: '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'',
             key: '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72',
             chain: '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'/2\'',
             key: '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d',
             chain: '5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4'}
        ]
    }];

    describe('BIP32-Ed25519 ExtendedKeyNode should', () => {
        extendedKeys.map((extendedKey) => {
            // create master key node
            const masterKey = ExtendedKeyNode.createFromSeed(
                extendedKey.seedHex,
                Network.CATAPULT
            );

            it (extendedKey.label + ': create correct master extended private key', () => {
                expect(masterKey.node.chainCode.toString('hex')).to.be.equal(extendedKey.chainCode);
                expect(masterKey.getPrivateKey()).to.be.equal(extendedKey.masterPrv);
            });

            it (extendedKey.label + ': create correct master extended public key', () => {
                expect(masterKey.getPublicKey()).to.be.equal(extendedKey.catapultPub);
            });

            it(extendedKey.label + ': derive correct extended public key given seed (' + (extendedKey.seedHex.length/2) + ' bytes) and paths', () => {

                // iterate through paths to derive
                extendedKey.neutered.map((neuteredKey) => {
                    const childDerived = masterKey.derivePath(neuteredKey.path);

                    // test chain code of derived node
                    expect(childDerived.node.chainCode.toString('hex')).to.be.equal(neuteredKey.chain);

                    // test `getPublicKey()` and *neutered node* `getPublicKey()`
                    expect(childDerived.getPublicKey()).to.be.equal(neuteredKey.key);
                    expect(childDerived.getPublicNode().getPublicKey()).to.be.equal(neuteredKey.key);
                });
            });

            it(extendedKey.label + ': derive correct extended private key given seed (' + (extendedKey.seedHex.length/2) + ' bytes)  and paths', () => {

                // iterate through paths to derive
                extendedKey.nonNeutered.map((nonNeuteredKey) => {
                    const childDerived = masterKey.derivePath(nonNeuteredKey.path);

                    // test chain code of derived node
                    expect(childDerived.node.chainCode.toString('hex')).to.be.equal(nonNeuteredKey.chain);

                    // test `getPrivateKey()` return, SLIP-10-compliant
                    expect(childDerived.getPrivateKey()).to.be.equal(nonNeuteredKey.key);
                });
            });
        });
    });

});
