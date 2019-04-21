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
import * as bip32 from 'bip32';
import {BIP32} from 'bip32';
import {expect} from "chai";
import {
    CurveAlgorithm,
    NodeInterface,
    NodeImpl,
    NodeEd25519,
} from "../index";

describe('NodeImpl<T> -->', () => {

    const seed = '000102030405060708090a0b0c0d0e0f';

    describe('constructor() should', () => {
        it('fill node object with BIP32 object', () => {
            const impl = new NodeImpl<BIP32>(bip32.fromSeed(Buffer.from(seed, 'hex')));

            //XXX `BIP32` class cannot be used as a right-hand operator of instanceof
            expect(impl.node).to.not.be.instanceof(NodeEd25519);

            // presence checks instead of type check
            expect(impl.node.privateKey).to.not.be.undefined;
            expect(impl.node.publicKey).to.not.be.undefined;
            expect(impl.node.chainCode).to.not.be.undefined;

            // + value integrity check
            expect(impl.node.privateKey.byteLength).to.be.equal(32);
            expect(impl.node.chainCode.byteLength).to.be.equal(32);
            expect(impl.node.publicKey.byteLength).to.be.equal(33);
        });

        it('fill node object with NodeEd25519 object', () => {
            const impl = new NodeImpl<NodeInterface>(NodeEd25519.fromSeed(Buffer.from(seed, 'hex')));

            expect(impl.node).to.be.instanceof(NodeEd25519);

            // presence checks
            expect(impl.node.privateKey).to.not.be.undefined;
            expect(impl.node.publicKey).to.not.be.undefined;
            expect(impl.node.chainCode).to.not.be.undefined;
            expect(impl.node.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // + value integrity check
            expect(impl.node.privateKey.byteLength).to.be.equal(32);
            expect(impl.node.chainCode.byteLength).to.be.equal(32);

            // IMPORTANT: Catapult public keys are 32 bytes but BIP32 requires 33-bytes!
            expect(impl.node.publicKey.byteLength).to.be.equal(32);
        });
    });

});
