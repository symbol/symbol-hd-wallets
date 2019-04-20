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
import { ExtendedKey } from "../src/ExtendedKey";

describe('BIP32-Ed15519 Extended Keys -->', () => {

    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    const extendedKeys = [
    // Test vector 1: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    {
        label: 'Vector #1',
        seedHex: '000102030405060708090a0b0c0d0e0f',
        masterPub: '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed',
        masterPrv: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
        neutered: [
            {path: 'm/0\'', 
             key: '008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'},
            {path: 'm/0\'/1\'',
             key: '001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'},
            {path: 'm/0\'/1\'/2\'',
             key: '00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1'},
            {path: 'm/0\'/1\'/2\'/2\'',
             key: '008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c'},
            {path: 'm/0\'/1\'/2\'/2\'/1000000000\'',
             key: '003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'},
        ],
        nonNeutered: [
            {path: 'm/0\'', 
             key: '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'},
            {path: 'm/0\'/1\'',
             key: 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2'},
            {path: 'm/0\'/1\'/2\'',
             key: '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9'},
            {path: 'm/0\'/1\'/2\'/2\'',
             key: '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662'},
            {path: 'm/0\'/1\'/2\'/2\'/1000000000\'',
             key: '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793'},
        ],
    },
    // Test vector 2: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    {
        label: 'Vector #2',
        seedHex: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        masterPub: '008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a',
        masterPrv: '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012',
        neutered: [
            {path: 'm/0\'',
             key: '0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037'},
            {path: 'm/0\'/2147483647\'',
             key: '005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d'},
            {path: 'm/0\'/2147483647\'/1\'',
             key: '002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'',
             key: '00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'/2\'',
             key: '0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0'},
        ],
        nonNeutered: [
            {path: 'm/0\'',
             key: '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635'},
            {path: 'm/0\'/2147483647\'',
             key: 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4'},
            {path: 'm/0\'/2147483647\'/1\'',
             key: '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'',
             key: '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72'},
            {path: 'm/0\'/2147483647\'/1\'/2147483646\'/2\'',
             key: '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d'},
        ]
    }];

    describe('BIP32-Ed25519 ExtendedKeyNode should', () => {
        extendedKeys.map((extendedKey) => {
            // create master key node
            const masterKey = ExtendedKeyNode.createFromSeed(extendedKey.seedHex);

            it (extendedKey.label + ': create correct master extended private key', () => {
                expect(masterKey.getPrivateKey()).to.be.equal(extendedKey.masterPrv);
            });

            it (extendedKey.label + ': create correct master extended public key', () => {
                const masterPub = masterKey.getPublicNode();
                expect(masterPub.getPublicKey()).to.be.equal(extendedKey.masterPub);
            });

            it(extendedKey.label + ': derive correct extended public key given seed (' + (extendedKey.seedHex.length/2) + ' bytes) and paths', () => {

                // iterate through paths to derive
                extendedKey.neutered.map(
                    (neuteredKey) => {
                        const childDerived = masterKey.derivePath(neuteredKey.path);
                        expect(childDerived.getPublicNode().getPublicKey()).to.be.equal(neuteredKey.key);
                    });
            });

            it(extendedKey.label + ': derive correct extended private key given seed (' + (extendedKey.seedHex.length/2) + ' bytes)  and paths', () => {

                // iterate through paths to derive
                extendedKey.nonNeutered.map(
                    (nonNeuteredKey) => {
                        const childDerived = masterKey.derivePath(nonNeuteredKey.path);
                        expect(childDerived.getPrivateKey()).to.be.equal(nonNeuteredKey.key);
                    });
            });
        });
    });

});
