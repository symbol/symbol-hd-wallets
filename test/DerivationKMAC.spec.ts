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
 *
 */
describe('BIP32-Ed15519 KMAC derivation -->', () => {

    const seed = '000102030405060708090a0b0c0d0e0f';

    describe('ExtendedKey.createFromSeed() should', () => {
        it('use MACType.HMAC as default MAC type', () => {
            const masterKey = ExtendedKey.createFromSeed(
                seed,
                Network.CATAPULT
            );

            expect(masterKey.macType).to.be.equal(MACType.HMAC);
        });

        it('permit specialization of macType property', () => {
            const kmacKey = ExtendedKey.createFromSeed(
                seed,
                Network.CATAPULT,
                MACType.KMAC
            );

            expect(kmacKey.macType).to.be.equal(MACType.KMAC);
        });
    });

});
