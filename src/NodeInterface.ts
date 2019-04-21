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
// internal dependencies
import { 
    Network,
} from '../index';

/**
 * Interface `NodeInterface` defines ground rules for
 * BIP32 node implementation for different curves than
 * secp256k1 and ed25519.
 *
 * @see https://github.com/nemtech/NIP/issues/12
 * @since 0.2.0
 */
export interface NodeInterface {
    privateKey: Buffer;
    publicKey: Buffer;
    network: Network;
    chainCode: Buffer;

    isNeutered(): boolean;
    neutered(): NodeInterface;
    toBase58(): string;
    toWIF(): string;
    derive(index: number): NodeInterface;
    deriveHardened(index: number): NodeInterface;
    derivePath(path: string): NodeInterface;
    sign(hash: Buffer): Buffer;
    verify(hash: Buffer, signature: Buffer): boolean;

    // Public getter addons
    getD(): Buffer | undefined;
    getQ(): Buffer | undefined;
    getDepth(): number;
    getIndex(): number;
    getParentFingerprint(): number;
}
