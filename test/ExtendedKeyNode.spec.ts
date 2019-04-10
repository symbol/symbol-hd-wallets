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
import {ExtendedKeyNode} from "../index";

describe('ExtendedKeyNode -->', () => {

    const seed = '000102030405060708090a0b0c0d0e0f';
    const extendedKeys = {
        neutered: [
            {path: 'm', key: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'},
            {path: 'm/0', key: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'},
            {path: 'm/0/1', key: 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'},
            {path: 'm/0/1/2', key: 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'},
            {path: 'm/0/1/2/2', key: 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'},
            {path: 'm/0H/1/2H/2/1000000000', key: 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'},
        ],
        nonNeutered: [
            {path: 'm', key: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'},
            {path: 'm/0', key: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'},
            {path: 'm/0/1', key: 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'},
            {path: 'm/0/1/2', key: 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'},
            {path: 'm/0/1/2/2', key: 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'},
            {path: 'm/0H/1/2H/2/1000000000', key: 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'},
        ],
    }

    describe('constructor should', () => {

        it('should parse master key with payload for "m" path', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[0].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[0].key));

            expect(neuteredMaster.isMaster()).to.be.equal(true);
            expect(nonNeuteredMaster.isMaster()).to.be.equal(true);
        });

        it('should parse child key with payload for "m/0" path', () => {
            const neuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.neutered[1].key));
            const nonNeuteredMaster = new ExtendedKeyNode(bip32.fromBase58(extendedKeys.nonNeutered[1].key));

            expect(neuteredMaster.isMaster()).to.be.equal(false);
            expect(nonNeuteredMaster.isMaster()).to.be.equal(false);
        });

        it('should parse neutered from neutered keys', () => {

            extendedKeys.neutered.map(
                (neuteredKey) => {
                    const neuteredNode = new ExtendedKeyNode(bip32.fromBase58(neuteredKey.key));
                    expect(neuteredNode.isNeutered()).to.be.equal(true);
                });
        });

        it('should parse non-neutered from non-neutered keys', () => {

            extendedKeys.nonNeutered.map(
                (nonNeuteredKey) => {
                    const nonNeuteredNode = new ExtendedKeyNode(bip32.fromBase58(nonNeuteredKey.key));
                    expect(nonNeuteredNode.isNeutered()).to.be.equal(false);
                });
        });

    });

});
