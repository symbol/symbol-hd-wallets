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
    Account,
    PublicAccount,
    NetworkType,
} from 'nem2-sdk';

// internal dependencies
import { 
    ExtendedKey,
    KeyEncoding,
    Network,
} from '../index';

/**
 * Class `Wallet` describes a hierarchical deterministic Wallet that
 * produces _Catapult-ED25519_-compatible accounts.
 *
 * This class provides with a bridge between BIP32-ED25519 compatible
 * key pairs and the nem2-sdk `Account` or `PublicAccount` objects.
 *
 * @example Usage of hierarchical deterministic wallets
 * 
 * ```typescript
 * const xkey = ExtendedKey.createFromSeed('000102030405060708090a0b0c0d0e0f');
 * const wallet = new Wallet(xkey);
 * 
 * // get master account
 * const masterAccount = wallet.getAccount();
 * 
 * // get DEFAULT WALLET
 * const defaultWallet = wallet.getChildAccount();
 * 
 * // derive specific child path
 * const childWallet = wallet.getChildAccount('m/44\'/43\'/0\'/0\'/0\'');
 * ```
 *
 * @see https://github.com/nemtech/NIP/issues/12
 * @since 0.3.0
 */
export class Wallet {

    /**
     * The default wallet derivaton path.
     * @var {string}
     */
    public static DEFAULT_WALLET_PATH = 'm/44\'/43\'/0\'/0\'/0\'';

    /**
     * Whether the wallet is read-only or not.
     * @var {boolean}
     */
    protected readOnly: boolean = false;

    /**
     * The wallet public key.
     * @var {Buffer}
     */
    protected publicKey: Buffer;

    /**
     * Construct a `Wallet` object from an extended key.
     *
     * @param   extendedKey   {ExtendedKey}
     */
    constructor(/**
                 * The extended key.
                 * @var {ExtendedKey}
                 */
                public readonly extendedKey: ExtendedKey,
    ) {
        // with an extended public key we have a read-only wallet
        if (extendedKey.isNeutered()) {
            this.readOnly = true;
        }

        this.publicKey = extendedKey.getPublicKey(KeyEncoding.ENC_BIN) as Buffer;
    }

    /**
     * Return whether the current wallet is read-only, or not.
     *
     * In case of an initialization with an extended *public* key,
     * the wallet is set to be read-only.
     *
     * @return  {boolean}
     */
    isReadOnly(): boolean {
        return this.readOnly;
    }

    /**
     * Get a nem2-sdk `Account` object with the extended
     * key property.
     *
     * No derivation is done in this step. Derivation must be done either before
     * calling this method or using the `getChildAccount` method.
     *
     * @param   networkType {NetworkType}   Which network type to use, defaults to MIJIN_TEST.
     * @return  {Account}
     * @throws  {Error}     On call of this method with a read-only wallet.
     */
    getAccount(
        networkType: NetworkType = NetworkType.MIJIN_TEST
    ): Account {

        // in case of read-only wallet, not possible to initiate Account
        // only PublicAccount can be used, see getPublicAccount().
        if (this.readOnly) {
            throw new Error("Missing private key, please use method getPublicAccount().");
        }

        // note: do not store private key in memory longer than function call
        return Account.createFromPrivateKey(
            this.extendedKey.getPrivateKey(KeyEncoding.ENC_HEX) as string,
            networkType
        );
    }

    /**
     * Get a nem2-sdk `PublicAccount` object with the extended key property.
     *
     * No derivation is done in this step. Derivation must be done either before
     * calling this method or using the `getChildPublicAccount` method.
     *
     * @param   networkType {NetworkType}   Which network type to use, defaults to MIJIN_TEST.
     * @return  {PublicAccount}
     */
    getPublicAccount(
        networkType: NetworkType = NetworkType.MIJIN_TEST
    ): PublicAccount {

        return PublicAccount.createFromPublicKey(
            this.publicKey.toString('hex'),
            networkType
        );
    }

    /**
     * Get a nem2-sdk `Account` object with the derived child account.
     *
     * In case no derivation path is provided, the default wallet path
     * will be used, see `Wallet.DEFAULT_WALLET_PATH`.
     *
     * @see Wallet.DEFAULT_WALLET_PATH
     * @param   path        {string}        Child derivation path, default to `Wallet.DEFAULT_WALLET_PATH`.
     * @param   networkType {NetworkType}   Which network type to use, defaults to MIJIN_TEST.
     * @return  {Account | PublicAccount}
     * @throws  {Error}     On call of this method with a read-only wallet.
     */
    getChildAccount(
        path: string = Wallet.DEFAULT_WALLET_PATH,
        networkType: NetworkType = NetworkType.MIJIN_TEST
    ): Account {

        // in case of read-only wallet, get PublicAccount instance
        if (this.readOnly) {
            throw new Error("Missing private key, please use method getChildPublicAccount().");
        }

        // child key derivation with `ExtendedKeyNode.derivePath()`
        const childKeyNode = this.extendedKey.derivePath(path);

        // non-read-only, get Account instance
        return Account.createFromPrivateKey(
            childKeyNode.getPrivateKey(KeyEncoding.ENC_HEX) as string,
            networkType
        );
    }

    /**
     * Get a nem2-sdk `PublicAccount` object with the derived child account.
     *
     * In case no derivation path is provided, the default wallet path
     * will be used, see `Wallet.DEFAULT_WALLET_PATH`.
     *
     * @see Wallet.DEFAULT_WALLET_PATH
     * @param   path        {string}        Child derivation path, default to `Wallet.DEFAULT_WALLET_PATH`.
     * @param   networkType {NetworkType}   Which network type to use, defaults to MIJIN_TEST.
     * @return  {Account | PublicAccount}
     */
    getChildPublicAccount(
        path: string = Wallet.DEFAULT_WALLET_PATH,
        networkType: NetworkType = NetworkType.MIJIN_TEST
    ): PublicAccount {

        // child key derivation with `ExtendedKeyNode.derivePath()`
        const childKeyNode = this.extendedKey.derivePath(path);
        return PublicAccount.createFromPublicKey(
            childKeyNode.getPublicKey(KeyEncoding.ENC_HEX) as string,
            networkType
        );
    }

}
