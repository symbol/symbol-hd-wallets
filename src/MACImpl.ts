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
    Cryptography,
    MACType,
} from '../index';

/**
 * Enumeration `MACImpl` describes multiple message authentication
 * code implementations.
 *
 * @see https://github.com/nemtech/NIP/issues/12
 * @since 0.3.0
 */
export class MACImpl {

    /**
     * No-Construct
     */
    private constructor() {}

    /**
     * Create a message authentication code with given `type`.
     * This will use either of HMAC or KMAC code generation.
     * 
     * @access public
     * @param   type        {MACType}
     * @param   key         {Buffer}
     * @param   data        {Buffer}
     * @param   publicSalt  {Buffer|undefined}  (Optional)
     */
    public static create(
        type: MACType,
        key: Buffer,
        data: Buffer,
        publicSalt: Buffer | undefined = undefined,
    ) {
        if (MACType.KMAC === type) {
            // use KMAC256
            return Cryptography.KMAC(key, data, publicSalt);
        }

        // by default uses HMAC with SHA512
        return Cryptography.HMAC(key, data);
    }
}
