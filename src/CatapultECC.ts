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
import {array, nacl_catapult, sha3Hasher} from 'nem2-library';

// internal dependencies
import {
    HasherInterface,
} from '../index';

export class CatapultECC {

    public static readonly KEY_SIZE: number = 32;
    public static readonly SIGNATURE_SIZE: number = 64;
    public static readonly HALF_SIGNATURE_SIZE: number = CatapultECC.SIGNATURE_SIZE / 2;
    public static readonly HASH_SIZE: number = 64;
    public static readonly HALF_HASH_SIZE: number = CatapultECC.HASH_SIZE / 2;

    /**
     * 
     */
    protected static encodedSChecker = (function () {
        const Is_Reduced = 1;
        const Is_Zero = 2;

        function validateEncodedSPart(
            s: Uint8Array
        ): number {
            if (array.isZero(s))
                return Is_Zero | Is_Reduced;

            const copy = new Uint8Array(CatapultECC.SIGNATURE_SIZE);
            array.copy(copy, s, CatapultECC.HALF_SIGNATURE_SIZE);

            nacl_catapult.reduce(copy);
            return array.deepEqual(s, copy, CatapultECC.HALF_SIGNATURE_SIZE) ? Is_Reduced : 0;
        }

        return {
            isCanonical: (s: Uint8Array): boolean => Is_Reduced === validateEncodedSPart(s),

            requireValid: (s: Uint8Array): void => {
                if (0 === (validateEncodedSPart(s) & Is_Reduced))
                    throw Error('S part of signature invalid');
            }
        };
    })();

    /**
     * 
     * @param d 
     */
    protected static clamp(
        d: Uint8Array
    ): void {
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
    }

    /**
     * 
     * @param sk 
     * @param hashfunc 
     */
    protected static prepareForScalarMult(
        sk: Uint8Array,
        hashfunc: Function
    ): Uint8Array {
        const d = new Uint8Array(CatapultECC.HASH_SIZE);
        hashfunc(d, sk);
        CatapultECC.clamp(d);
        return d;
    }

    public static extractPublicKey(
        sk: Uint8Array,
        hashfunc: Function
    ): Uint8Array {
        const c = nacl_catapult;
        const d = CatapultECC.prepareForScalarMult(sk, hashfunc);

        const p = [c.gf(), c.gf(), c.gf(), c.gf()];
        const pk = new Uint8Array(CatapultECC.KEY_SIZE);
        c.scalarbase(p, d);
        c.pack(pk, p);
        return pk;
    }

    public static sign(
        m: Uint8Array,
        pk: Uint8Array,
        sk: Uint8Array,
        hasher: HasherInterface
    ): Uint8Array {
        const c = nacl_catapult;

        const d = new Uint8Array(CatapultECC.HASH_SIZE);
        hasher.reset();
        hasher.update(sk);
        hasher.finalize(d);
        CatapultECC.clamp(d);

        const r = new Uint8Array(CatapultECC.HASH_SIZE);
        hasher.reset();
        hasher.update(d.subarray(CatapultECC.HALF_HASH_SIZE));
        hasher.update(m);
        hasher.finalize(r);

        const p = [c.gf(), c.gf(), c.gf(), c.gf()];
        const signature = new Uint8Array(CatapultECC.SIGNATURE_SIZE);
        c.reduce(r);
        c.scalarbase(p, r);
        c.pack(signature, p);

        const h = new Uint8Array(CatapultECC.HASH_SIZE);
        hasher.reset();
        hasher.update(signature.subarray(0, CatapultECC.HALF_SIGNATURE_SIZE));
        hasher.update(pk);
        hasher.update(m);
        hasher.finalize(h);

        c.reduce(h);

        // muladd
        const x = new Float64Array(CatapultECC.HASH_SIZE);
        array.copy(x, r, CatapultECC.HALF_HASH_SIZE);

        for (let i = 0; i < CatapultECC.HALF_HASH_SIZE; ++i) {
            for (let j = 0; j < CatapultECC.HALF_HASH_SIZE; ++j)
                x[i + j] += h[i] * d[j];
        }

        c.modL(signature.subarray(CatapultECC.HALF_SIGNATURE_SIZE), x);
        CatapultECC.encodedSChecker.requireValid(signature.subarray(CatapultECC.HALF_SIGNATURE_SIZE));
        return signature;
    }

    public static verify(
        pk: Uint8Array,
        m: Uint8Array,
        signature: Uint8Array,
        hasher: HasherInterface
    ): boolean {
        // reject non canonical signature
        if (!CatapultECC.encodedSChecker.isCanonical(signature.subarray(CatapultECC.HALF_SIGNATURE_SIZE)))
            return false;

        // reject weak (zero) public key
        if (array.isZero(pk))
            return false;

        const c = nacl_catapult;
        const p = [c.gf(), c.gf(), c.gf(), c.gf()];
        const q = [c.gf(), c.gf(), c.gf(), c.gf()];

        if (c.unpackneg(q, pk))
            return false;

        const h = new Uint8Array(CatapultECC.HASH_SIZE);
        hasher.reset();
        hasher.update(signature.subarray(0, CatapultECC.HALF_SIGNATURE_SIZE));
        hasher.update(pk);
        hasher.update(m);
        hasher.finalize(h);

        c.reduce(h);
        c.scalarmult(p, q, h);

        const t = new Uint8Array(CatapultECC.SIGNATURE_SIZE);
        c.scalarbase(q, signature.subarray(CatapultECC.HALF_SIGNATURE_SIZE));
        c.add(p, q);
        c.pack(t, p);

        return 0 === c.crypto_verify_32(signature, 0, t, 0);
    }

    public static deriveSharedKey(
        salt: Uint8Array,
        sk: Uint8Array,
        pk: Uint8Array,
        hashfunc: Function
    ): Uint8Array {
        const c = nacl_catapult;
        const d = CatapultECC.prepareForScalarMult(sk, hashfunc);

        // sharedKey = pack(p = d (derived from sk) * q (derived from pk))
        const q = [c.gf(), c.gf(), c.gf(), c.gf()];
        const p = [c.gf(), c.gf(), c.gf(), c.gf()];
        const sharedKey = new Uint8Array(CatapultECC.KEY_SIZE);
        c.unpackneg(q, pk);
        c.scalarmult(p, q, d);
        c.pack(sharedKey, p);

        // salt the shared key
        for (let i = 0; i < CatapultECC.KEY_SIZE; ++i)
            sharedKey[i] ^= salt[i];

        // return the hash of the result
        const sharedKeyHash = new Uint8Array(CatapultECC.KEY_SIZE);
        hashfunc(sharedKeyHash, sharedKey, CatapultECC.KEY_SIZE);
        return sharedKeyHash;
    }
}
