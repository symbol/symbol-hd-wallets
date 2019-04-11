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
import { ExtendedKeyNode } from '../index';

/**
 * Class `ExtendedKey` describes an extended key as described in 
 * the Bitcoin BIP32 standard which can be found at following
 * URL:
 *
 *     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * It will be adapted to work with ED25519 ellyptic curve because BIP32
 * is only compatible with secp256k1 ellyptic curve.
 * 
 * The work on this BIP32-ED25519 will be discussed and described in 
 * the following [NIP](https://github.com/nemtech/NIP/issues/12): 
 *
 *     https://github.com/nemtech/NIP/issues/12
 *
 * This class *uses* features provided by the `bitcoinjs/bip32` package
 * and therefor is licensed under the BSD-2 Clause License as mentioned
 * [here](https://github.com/bitcoinjs/bip32/blob/master/LICENSE).
 * 
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/bitcoinjs/bip32
 * @see https://github.com/nemtech/NIP/issues/12
 * @since 0.1.0
 */
export class ExtendedKey {

    protected node: ExtendedKeyNode;

    /**
     * Construct an `ExtendedKey` object out of its' base58 payload.
     *
     * @example Example of `payload` values include:
     *
     *   `xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8`
     *   `xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi`
     *   `xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw`
     *   `xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7`
     *
     * @see 
     * @param   base58Payload   {string}
     */
    constructor(/**
                 * The Base58 payload of the extended key.
                 * @var {string}
                 */
                public readonly base58Payload: string
    ) {
        this.node = ExtendedKeyNode.createFromBase58(base58Payload);
    }

    /**
     * Create a child private key from an extended key.
     * 
     * This is possible only with **not-neutered** extended key nodes.
     * 
     * @param   derivationPath  {string}    Example: "m/44'/43'/0'/0/0"
     * @return  {ExtendedKey}
     * @throws  {Error}     On use of this method with neutered extended keys (public keys).
     */
    getChildPrivateKey(
        derivationPath: string
    ): ExtendedKey {
        if (this.node.isNeutered()) {
            throw new Error('Cannot derive child private key out of extended public key.');
        }

        const child = this.node.derivePath(derivationPath);
        return new ExtendedKey(child.toBase58());
    }

    /**
     * Create a child public key from an extended key.
     * 
     * This is possible with either of neutered and non-neutered extended
     * key nodes.
     *
     * @param   derivationPath  {string}    Example: "m/44'/43'/0'/0/0"
     * @return  {ExtendedKey}
     */
    getChildPublicKey(
        derivationPath: string
    ): ExtendedKey {
        const child = this.node.derivePath(derivationPath);
        return new ExtendedKey(child.toBase58());
    }

}