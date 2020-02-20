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

// internal dependencies
import {
    CurveAlgorithm,
    Network,
} from "../index";

describe('Network -->', () => {

    describe('constructor() should', () => {

        it('set correct privateKeyPrefix and publicKeyPrefix', () => {
            const network1 = new Network(1, 2, CurveAlgorithm.secp256k1)
            const network2 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.secp256k1)

            expect(network1.publicKeyPrefix).to.be.equal(1);
            expect(network1.privateKeyPrefix).to.be.equal(2);
            expect(network2.publicKeyPrefix).to.be.equal(0x0488b21e);
            expect(network2.privateKeyPrefix).to.be.equal(0x0488ade4);
        });

        it('set correct curve algorithm', () => {
            const network1 = new Network(1, 2, CurveAlgorithm.secp256k1)
            const network2 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.ed25519)
            const network3 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.ed25519)

            expect(network1.curve).to.be.equal(CurveAlgorithm.secp256k1)
            expect(network2.curve).to.be.equal(CurveAlgorithm.ed25519)
            expect(network3.curve).to.be.equal(CurveAlgorithm.ed25519)
        });
    });

    describe('equals() should', () => {
        it('return false given non-identical object', () => {
            const network1 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.ed25519)
            const network2 = new Network(1, 2, CurveAlgorithm.ed25519)
            expect(network1.equals(network2)).to.be.equal(false)
        });

        it('return true given identical object', () => {
            const network1 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.ed25519)
            const network2 = new Network(0x0488b21e, 0x0488ade4, CurveAlgorithm.ed25519)
            expect(network1.equals(network2)).to.be.equal(true)
        });
    });
});
