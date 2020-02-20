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
    Convert,
    NetworkType,
} from 'nem2-sdk';

// internal dependencies
import {
    ExtendedKey,
    Network,
    NodeEd25519,
} from "../index";

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
    {
        label: 'Vector #1',
        seedHex: '000102030405060708090a0b0c0d0e0f',
        chainCode: '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb',
        masterPub: 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed',
        masterPrv: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
        neutered: [
            {path: 'm/0\'',
             key: '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c',
             chain: '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69'},
            {path: 'm/0\'/1\'',
             key: '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187',
             chain: 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14'},
            {path: 'm/0\'/1\'/2\'',
             key: 'ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1',
             chain: '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c'},
            {path: 'm/0\'/1\'/2\'/2\'',
             key: '8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c',
             chain: '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc'},
            {path: 'm/0\'/1\'/2\'/2\'/1000000000\'',
             key: '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a',
             chain: '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230'},
             {path: 'm/44\'/43\'/0\'/0\'/0\'',
             key: '2daecee59b39e0e1095005162cf2879c30a21c1868f0474eba02d41bd1d0f969',
             chain: 'c428a9ed5355167f312292c4e4ef3aae680145009197c4f6b23bfeed0780643e'},
             {path: 'm/44\'/43\'/1\'/0\'/0\'',
             key: '0ad5eb7d7c2d0f0e673651732d415b54333adb8a5a67fbce7b07852b355d457a',
             chain: '5619e49ec9c210ac75e89000e9c3266a388ae913615449790c4cbefff990b00e'},
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
             {path: 'm/44\'/43\'/0\'/0\'/0\'',
             key: '4ce1c399f5f72acf16e7231a406f6e8284033f686d565100fed376960ea8c871',
             chain: 'c428a9ed5355167f312292c4e4ef3aae680145009197c4f6b23bfeed0780643e'},
             {path: 'm/44\'/43\'/1\'/0\'/0\'',
             key: '1b05cb9db696df7216bd6a551c0e2b441234a59b23d785f4c803a41d64ce4d69',
             chain: '5619e49ec9c210ac75e89000e9c3266a388ae913615449790c4cbefff990b00e'},
        ],
    },
    // Test vector 2: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    {
        label: 'Vector #2',
        seedHex: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        chainCode: 'ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b',
        masterPub: '8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a',
        masterPrv: '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012',
        neutered: [
            {path: 'm/0\'',
             key: '86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037',
             chain: '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d'},
            {path: 'm/0\'/2147483647\'',
             key: '5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d',
             chain: '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f'},
            {path: 'm/0\'/2147483647\'/1\'',
             key: '2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45',
             chain: '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'',
             key: 'e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b',
             chain: '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'/2\'',
             key: '47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0',
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

    describe('BIP32-Ed25519 ExtendedKey should', () => {
        extendedKeys.map((extendedKey) => {
            // create master key node
            const masterKey = ExtendedKey.createFromSeed(
                extendedKey.seedHex,
                Network.CATAPULT
            );

            it (extendedKey.label + ': create correct master extended private key', () => {
                expect(masterKey.node.chainCode.toString('hex')).to.be.equal(extendedKey.chainCode);
                expect(masterKey.getPrivateKey()).to.be.equal(extendedKey.masterPrv);
            });

            it (extendedKey.label + ': create correct master extended public key', () => {
                expect(masterKey.getPublicKey()).to.be.equal(extendedKey.masterPub);
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

    describe('NodeEd25519 should', () => {
        it('forward network property in CKDPriv (derivePath) and derive correct public key with SHA3', () => {
            const privateKey = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPublicKey = '2e834140fd66cf87b254a693a2c7862c819217b676d3943267156625e816ec6f';

            const privateBytes = Convert.hexToUint8(privateKey);
            const node = new NodeEd25519(Buffer.from(privateBytes), undefined, Buffer.from(''), Network.CATAPULT);

            expect(node.publicKey.toString('hex')).to.equal(expectPublicKey);
        });

        it('forward network property in CKDPriv (derivePath) and derive correct public key with REVERSED private key', () => {
            const privateKey = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPublicKey = '5112ba143b78132af616af1a94e911ead890fdb51b164a1b57c352ecd9ca1894';

            // REVERSED private key (NIS)
            const privateBytes = Convert.hexToUint8Reverse(privateKey);
            const node = new NodeEd25519(Buffer.from(privateBytes), undefined, Buffer.from(''), Network.CATAPULT_PUBLIC);

            expect(node.publicKey.toString('hex')).to.equal(expectPublicKey);
        });
    });

});
