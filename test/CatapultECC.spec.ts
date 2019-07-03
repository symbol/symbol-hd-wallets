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
import {Crypto} from 'nem2-sdk';

// internal dependencies
import {
    CatapultECC,
    Cryptography,
} from "../index";

describe('CatapultECC -->', () => {

    const Private_Keys = [
        '8D31B712AB28D49591EAF5066E9E967B44507FC19C3D54D742F7B3A255CFF4AB',
        '15923F9D2FFFB11D771818E1F7D7DDCD363913933264D58533CB3A5DD2DAA66A',
        'A9323CEF24497AB770516EA572A0A2645EE2D5A75BC72E78DE534C0A03BC328E',
        'D7D816DA0566878EE739EDE2131CD64201BCCC27F88FA51BA5815BCB0FE33CC8',
        '27FC9998454848B987FAD89296558A34DEED4358D1517B953572F3E0AAA0A22D'
    ];

    describe('sign() should', () => {
        it('fill the signature', () => {

            // Arrange:
            const privateKey = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey = CatapultECC.extractPublicKey(privateKey, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);

            // Act:
            const signature = CatapultECC.sign(payload, publicKey, privateKey, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(signature).to.not.deep.equal(new Uint8Array(CatapultECC.SIGNATURE_SIZE));
        });

        it('return same signature for same data signed by same key pairs', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const privateKey_2 = CatapultECC.keyToUint8(Private_Keys[0]); // SAME
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);

            // Act:
            const signature1 = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));
            const signature2 = CatapultECC.sign(payload, publicKey_2, privateKey_2, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(signature2).to.deep.equal(signature1);
        });

        it('return different signature for same data signed by different key pairs', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const privateKey_2 = CatapultECC.keyToUint8(Private_Keys[1]); // DIFFERENT
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);

            // Act:
            const signature1 = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));
            const signature2 = CatapultECC.sign(payload, publicKey_2, privateKey_2, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(signature2).to.not.deep.equal(signature1);
        });

        it('not allow signing unsupported data type', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);

            // Assert:
            expect(() => {
                CatapultECC.sign({} as Uint8Array, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));
            }).to.throw('unsupported data type');
        });
    });

    describe('verify() should', () => {
        it('return true for data signed with same key pair', () => {
            // Arrange:
            const privateKey = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey = CatapultECC.extractPublicKey(privateKey, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);
            const signature = CatapultECC.sign(payload, publicKey, privateKey, Cryptography.createSha3Hasher(64));

            // Act:
            const isVerified = CatapultECC.verify(publicKey, payload, signature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isVerified).to.equal(true);
        });

        it('returns false for data signed with different key pair', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const privateKey_2 = CatapultECC.keyToUint8(Private_Keys[1]); // DIFFERENT
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);
            const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));

            // Act:
            const isVerified = CatapultECC.verify(publicKey_2, payload, signature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isVerified).to.equal(false);
        });

        it('returns false if signature has been modified', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);

            for (let i = 0; i < CatapultECC.SIGNATURE_SIZE; i += 4) {
                const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));
                signature[i] ^= 0xFF;

                // Act:
                const isVerified = CatapultECC.verify(publicKey_1, payload, signature, Cryptography.createSha3Hasher(64));

                // Assert:
                expect(isVerified, `signature modified at ${i}`).to.equal(false);
            }
        });

        it('returns false if payload has been modified', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(44);

            for (let i = 0; i < payload.length; i += 4) {
                const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));
                payload[i] ^= 0xFF;

                // Act:
                const isVerified = CatapultECC.verify(publicKey_1, payload, signature, Cryptography.createSha3Hasher(64));

                // Assert:
                expect(isVerified, `payload modified at ${i}`).to.equal(false);
            }
        });

        it('fails if public key is not on curve', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            publicKey_1.fill(0);
            publicKey_1[publicKey_1.length - 1] = 1;

            const payload = Crypto.randomBytes(100);
            const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));

            // Act:
            const isVerified = CatapultECC.verify(publicKey_1, payload, signature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isVerified).to.equal(false);
        });

        it('fails if public key does not correspond to private key', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const payload = Crypto.randomBytes(100);
            const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));

            for (let i = 0; i < publicKey_1.length; ++i)
                publicKey_1[i] ^= 0xFF;

            // Act:
            const isVerified = CatapultECC.verify(publicKey_1, payload, signature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isVerified).to.equal(false);
        });

        it('rejects zero public key', () => {
            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            publicKey_1.fill(0);

            const payload = Crypto.randomBytes(100);
            const signature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));

            // Act:
            const isVerified = CatapultECC.verify(publicKey_1, payload, signature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isVerified).to.equal(false);
        });

        it('cannot verify non canonical signature', () => {
            function scalarAddGroupOrder(scalar: Uint8Array) {
                // 2^252 + 27742317777372353535851937790883648493, little endian
                const Group_Order = [
                    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
                ];

                let r = 0;
                for (let i = 0; i < scalar.length; ++i) {
                    const t = scalar[i] + Group_Order[i];
                    scalar[i] += Group_Order[i] + r;
                    r = (t >> 8) & 0xFF;
                }
            }

            // Arrange:
            const privateKey_1 = CatapultECC.keyToUint8(Private_Keys[0]);
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash);
            const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
            const canonicalSignature = CatapultECC.sign(payload, publicKey_1, privateKey_1, Cryptography.createSha3Hasher(64));

            // this is signature with group order added to 'encodedS' part of signature
            const nonCanonicalSignature = canonicalSignature.slice();
            scalarAddGroupOrder(nonCanonicalSignature.subarray(32));

            // Act:
            const isCanonicalVerified = CatapultECC.verify(publicKey_1, payload, canonicalSignature, Cryptography.createSha3Hasher(64));
            const isNonCanonicalVerified = CatapultECC.verify(publicKey_1, payload, nonCanonicalSignature, Cryptography.createSha3Hasher(64));

            // Assert:
            expect(isCanonicalVerified).to.equal(true);
            expect(isNonCanonicalVerified).to.equal(false);
        });
    });
/*
    describe('test vectors', () => {
        const Input_Data = [
            '8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9',
            'e4a92208a6fc52282b620699191ee6fb9cf04daf48b48fd542c5e43daa9897763a199aaa4b6f10546109f47ac3564fade0',
            '13ed795344c4448a3b256f23665336645a853c5c44dbff6db1b9224b5303b6447fbf8240a2249c55',
            'a2704638434e9f7340f22d08019c4c8e3dbee0df8dd4454a1d70844de11694f4c8ca67fdcb08fed0cec9abb2112b5e5f89',
            'd2488e854dbcdfdb2c9d16c8c0b2fdbc0abb6bac991bfe2b14d359a6bc99d66c00fd60d731ae06d0'
        ];
        const Expected_Signatures = [
            'C9B1342EAB27E906567586803DA265CC15CCACA411E0AEF44508595ACBC47600D02527F2EED9AB3F28C856D27E30C3808AF7F22F5F243DE698182D373A9ADE03',
            '0755E437ED4C8DD66F1EC29F581F6906AB1E98704ECA94B428A25937DF00EC64796F08E5FEF30C6F6C57E4A5FB4C811D617FA661EB6958D55DAE66DDED205501',
            '15D6585A2A456E90E89E8774E9D12FE01A6ACFE09936EE41271AA1FBE0551264A9FF9329CB6FEE6AE034238C8A91522A6258361D48C5E70A41C1F1C51F55330D',
            'F6FB0D8448FEC0605CF74CFFCC7B7AE8D31D403BCA26F7BD21CB4AC87B00769E9CC7465A601ED28CDF08920C73C583E69D621BA2E45266B86B5FCF8165CBE309',
            'E88D8C32FE165D34B775F70657B96D8229FFA9C783E61198A6F3CCB92F487982D08F8B16AB9157E2EFC3B78F126088F585E26055741A9F25127AC13E883C9A05'
        ];

        function assertCanSignTestVectors(dataTransform) {
            // Sanity:
            expect(Private_Keys.length).equal(Input_Data.length);
            expect(Private_Keys.length).equal(Expected_Signatures.length);

            for (let i = 0; i < Private_Keys.length; ++i) {
                // Arrange:
                const inputData = dataTransform(Input_Data[i]);
                const keyPair = createKeyPairFromPrivateKeyString(Private_Keys[i]);

                // Act:
                const signature = sign(keyPair, inputData);

                // Assert:
                const message = `signing with ${Private_Keys[i]}`;
                expect(convert.uint8ToHex(signature), message).equal(Expected_Signatures[i]);
            }
        }

        it('can sign test vectors as hex string', () => {
            // Assert:
            assertCanSignTestVectors(data => data);
        });

        it('can sign test vectors as binary', () => {
            // Assert:
            assertCanSignTestVectors(data => convert.hexToUint8(data));
        });

        function assertCanVerifyTestVectors(dataTransform) {
            // Sanity:
            expect(Private_Keys.length).equal(Input_Data.length);
            expect(Private_Keys.length).equal(Expected_Signatures.length);

            for (let i = 0; i < Private_Keys.length; ++i) {
                // Arrange:
                const inputData = dataTransform(Input_Data[i]);
                const keyPair = createKeyPairFromPrivateKeyString(Private_Keys[i]);
                const signature = sign(keyPair, inputData);

                // Act:
                const isVerified = verify(keyPair.publicKey, inputData, signature);

                // Assert:
                const message = `verifying with ${Private_Keys[i]}`;
                expect(isVerified, message).equal(true);
            }
        }

        it('can verify test vectors as hex string', () => {
            // Assert:
            assertCanVerifyTestVectors(data => data);
        });

        it('can verify test vectors as binary', () => {
            // Assert:
            assertCanVerifyTestVectors(data => convert.hexToUint8(data));
        });
    });

    describe('derive shared key', () => {
        const Salt_Size = 32;

        it('fails if salt is wrong size', () => {
            // Arrange: create a salt that is too long
            const keyPair = test.random.keyPair();
            const publicKey = test.random.publicKey();
            const salt = test.random.bytes(Salt_Size + 1);

            // Act:
            expect(() => {
                deriveSharedKey(keyPair, publicKey, salt);
            })
                .to.throw('salt has unexpected size');
        });

        it('derives same shared key for both partners', () => {
            // Arrange:
            const keyPair1 = test.random.keyPair();
            const keyPair2 = test.random.keyPair();
            const salt = test.random.bytes(Salt_Size);

            // Act:
            const sharedKey1 = deriveSharedKey(keyPair1, keyPair2.publicKey, salt);
            const sharedKey2 = deriveSharedKey(keyPair2, keyPair1.publicKey, salt);

            // Assert:
            expect(sharedKey1).to.deep.equal(sharedKey2);
        });

        it('derives different shared keys for different partners', () => {
            // Arrange:
            const keyPair = test.random.keyPair();
            const publicKey1 = test.random.publicKey();
            const publicKey2 = test.random.publicKey();
            const salt = test.random.bytes(Salt_Size);

            // Act:
            const sharedKey1 = deriveSharedKey(keyPair, publicKey1, salt);
            const sharedKey2 = deriveSharedKey(keyPair, publicKey2, salt);

            // Assert:
            expect(sharedKey1).to.not.deep.equal(sharedKey2);
        });

        it('can derive deterministic shared key from well known inputs', () => {
            // Arrange:
            const privateKey = convert.hexToUint8('8F545C2816788AB41D352F236D80DBBCBC34705B5F902EFF1F1D88327C7C1300');
            const publicKey = convert.hexToUint8('BF684FB1A85A8C8091EE0442EDDB22E51683802AFA0C0E7C6FE3F3E3E87A8D72');
            const salt = convert.hexToUint8('422C39DF16AAE42A74A5597D6EE2D59CFB4EEB6B3F26D98425B9163A03DAA3B5');

            // Act:
            const sharedKey = deriveSharedKey({ privateKey }, publicKey, salt);

            // Assert:
            expect(convert.uint8ToHex(sharedKey)).to.equal('FF9623D28FBC13B6F0E0659117FC7BE294DB3385C046055A6BAC39EDF198D50D');
        });
    });
*/
});
