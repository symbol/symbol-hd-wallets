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

import { 
    SHA3Hasher as sha3Hasher,
} from 'nem2-sdk';
import { kmac256 } from 'js-sha3';
const createHash = require('create-hash');
const createHmac = require('create-hmac');

// internal dependencies
import {
    HasherInterface,
} from '../index';

export class Cryptography {
    /**
     *
     * @param buffer
     */
    public static hash160(
        buffer: Buffer
    ): Buffer {
        // step 1: SHA256(buffer)
        const sha256Hash: Buffer = createHash('sha256').update(buffer).digest();

        // step 2: RIPEMD160(shaHash)
        try {
            return createHash('rmd160').update(sha256Hash).digest();
        } catch (err) {
            return createHash('ripemd160').update(sha256Hash).digest();
        }
    }

    /**
     * Creates a Hash Message Authentication Code.
     *
     * This method uses SHA512 algorithm and `create-hmac`
     * dependency for the MAC generation.
     *
     * @param   key     {Buffer}
     * @param   data    {Buffer}
     * @return  {Buffer}
     */
    public static HMAC(
        key: Buffer,
        data: Buffer
    ): Buffer {
        return createHmac('sha512', key).update(data).digest();
    }

    /**
     * Creates a Keccak Message Authentication Code.
     *
     * @internal This method is used internally for key derivation
     * @param   key         {Buffer}
     * @param   data        {Buffer}
     * @param   publicSalt  {string}
     * @return  {Buffer}
     */
    public static KMAC(
        key: Buffer,
        data: Buffer,
        publicSalt: Buffer | undefined
    ): Buffer {
        const hex = kmac256(key, data, 512, publicSalt || '');
        return Buffer.from(hex, 'hex');
    }

    /**
     * Calculates the hash of data.
     * @param {Uint8Array} dest The computed hash destination.
     * @param {Uint8Array} data The data to hash.
     * @param {numeric} length The hash length in bytes.
     */
    public static sha3Hash(
        dest: Uint8Array,
        data: Uint8Array,
        length: number = 64,
    ): Uint8Array {
        sha3Hasher.func(dest, data, length);
        return dest;
    }

    /**
     * Creates a SHA3 hasher object.
     * @param {numeric} length The hash length in bytes.
     * @returns {object} The hasher.
     */
    public static createSha3Hasher(
        length: number = 64,
    ): HasherInterface {
        return sha3Hasher.createHasher(length);
    }
}
