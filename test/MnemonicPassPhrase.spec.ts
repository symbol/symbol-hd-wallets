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
import {MnemonicPassPhrase} from "../index";

describe('MnemonicPassPhrase -->', () => {

    describe('MnemonicPassPhrase.createRandom should', () => {
        it('be created randomly without arguments', () => {
            const mnemonic = MnemonicPassPhrase.createRandom();
            const words = mnemonic.split(' ');

            expect(words.length).to.be.equal(24);
        });

        it('be created randomly with valid arguments', () => {
            const mnemonic = MnemonicPassPhrase.createRandom('english', 256);
            const words = mnemonic.split(' ');

            expect(words.length).to.be.equal(24);
        });

        it('only allow valid strength', () => {
            expect((function () {
                const invalidStrength = 64;
                MnemonicPassPhrase.createRandom('english', invalidStrength);
            })).to.throw('Invalid strength, must be multiple of 32 with: 128 >= strength <= 256.');
        });

        it('only allow supported language', () => {
            const invalidLanguage = 'belgian';
            expect((function () {
                MnemonicPassPhrase.createRandom(invalidLanguage);
            })).to.throw('Language "' + invalidLanguage + '" is not supported.');
        });

        it('accept strength to change number of words', () => {
            const m24 = MnemonicPassPhrase.createRandom('english', 256);
            const m18 = MnemonicPassPhrase.createRandom('english', 192);
            const m12 = MnemonicPassPhrase.createRandom('english', 128);

            expect(m24.split(' ').length).to.be.equal(24);
            expect(m18.split(' ').length).to.be.equal(18);
            expect(m12.split(' ').length).to.be.equal(12);
        });
    });

});
