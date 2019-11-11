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
import {Convert, Crypto, SignSchema} from 'nem2-sdk';

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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);

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
            const publicKey = CatapultECC.extractPublicKey(privateKey, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
            const publicKey_2 = CatapultECC.extractPublicKey(privateKey_2, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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
            const publicKey_1 = CatapultECC.extractPublicKey(privateKey_1, Cryptography.sha3Hash, SignSchema.SHA3);
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

    describe('extractPublicKey() should', () => {
        it('extract correct public key from private key with SignSchema.SHA3', () => {
            const privateKey = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPublicKey = 'BD8D3F8B7E1B3839C650F458234AB1FF87CDB1EDA36338D9E446E27D454717F2'.toLowerCase();

            const extract = CatapultECC.extractPublicKey(
                Buffer.from(Convert.hexToUint8(privateKey)),
                Cryptography.sha3Hash,
                SignSchema.SHA3,
            );

            expect(Buffer.from(extract).toString('hex')).to.equal(expectPublicKey);
        });
        it('extract correct public key from private key with SignSchema.KECCAK', () => {
            const privateKey = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPublicKey = 'c5f54ba980fcbb657dbaaa42700539b207873e134d2375efeab5f1ab52f87844';

            const extract = CatapultECC.extractPublicKey(
                Buffer.from(Convert.hexToUint8Reverse(privateKey)), // REVERSE
                Cryptography.sha3Hash,
                SignSchema.KECCAK,
            );

            expect(Buffer.from(extract).toString('hex')).to.equal(expectPublicKey);
        });
    });
});
