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
// internal dependencies
import {
    CurveAlgorithm,
} from '../index';

/**
 * Class `Network` describes an extended key prefix of 4 bytes. This object
 * is defined by `public` and `private` fields containing the unsigned
 * integer value of the prefix.
 *
 * For the BITCOIN protocol, the prefixes result to `xprv` and `xpub`
 * for the mainnet network. 
 *
 * For the CATAPULT protocol, we will be using the same prefixes and 
 * extended key sizes and formats.
 *
 * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L19
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/bitcoinjs/bip32
 * @see https://github.com/nemtech/NIP/issues/12
 * @since 0.1.0
 */
export class Network {

    /**
     * BITCOIN protocol extended key prefixes
     *
     * Result in Base58 notation to `xpub` and `xprv`.
     *
     * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L19
     * @var {Network}
     */
    public static readonly BITCOIN: Network = new Network(
        0x0488b21e, // base58 'xpub'
        0x0488ade4, // base58 'xprv'
        CurveAlgorithm.secp256k1
    );

    /**
     * CATAPULT protocol extended key prefixes
     *
     * Result in Base58 notation to `xpub` and `xprv`.
     *
     * @var {Network}
     */
    public static readonly CATAPULT: Network = new Network(
        0x0488b21e, // base58 'xpub'
        0x0488ade4, // base58 'xprv'
        CurveAlgorithm.ed25519
    );

    /**
     * CATAPULT public network protocol extended key prefixes
     *
     * Result in Base58 notation to `xpub` and `xprv`.
     *
     * @var {Network}
     */
    public static readonly CATAPULT_PUBLIC: Network = new Network(
        0x0488b21e, // base58 'xpub'
        0x0488ade4, // base58 'xprv'
        CurveAlgorithm.ed25519
    );

    /**
     * Construct an `Network` object out of its' base58 payload.
     *
     * Result in Base58 notation to `xpub` and `xprv`.
     *
     * @param   base58Payload   {string}
     */
    constructor(/**
                 * Prefix for extended public key (4 bytes unsigned integer)
                 * @var {number}
                 */
                public readonly publicKeyPrefix: number,
                /**
                 * Prefix for extended private key (4 bytes unsigned integer)
                 * @var {number}
                 */
                public readonly privateKeyPrefix: number,
                /**
                 * The ellyptic curve algorithm
                 * @var {CurveAlgorithm}
                 */
                public readonly curve: CurveAlgorithm = CurveAlgorithm.secp256k1) {

    }

    /**
     * Checks whether current network instance **is identical**
     * to given `b` network instance.
     *
     * @param   b       {Network}   The network object to compare against
     * @return  {boolean}   Returns whether the two objects are identical
     */
    public equals(b: Network): boolean {
        return this.privateKeyPrefix === b.privateKeyPrefix
            && this.publicKeyPrefix === b.publicKeyPrefix
            && this.curve === b.curve
    }
}