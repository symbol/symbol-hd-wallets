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
import { expect } from 'chai';
// internal dependencies
import {
    ExtendedKey
} from '../index';
import { Network } from '../src/Network';


describe('BIP32 Compatibility -->', () => {

    describe('ExtendedKey should', () => {
        it('throw for hardened derivation with extended public key', () => {
            expect(() => {
                // create master key node
                const masterKey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f', Network.BITCOIN);
                const masterPub = masterKey.getPublicNode();

                // use hardened path to produce error because `masterPub` is neutered
                const ignored = masterPub.derivePath('m/0\'');
            }).to.throw('Missing private key for hardened child key');
        });

        it('throw given seed length smaller than 16 (seed of 8 bytes)', () => {
            expect(() => {
                // create master key node
                const ignored = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f'.substr(0, 16), Network.BITCOIN);
            }).to.throw('Seed should be at least 128 bits');
        });

        it('throw given seed length bigger than 64 (seed of 96 bytes)', () => {
            expect(() => {
                // create master key node
                const ignored = ExtendedKey.createFromSeed('00'.repeat(96), Network.BITCOIN);
            }).to.throw('Seed should be at most 512 bits');
        });
    });

});
