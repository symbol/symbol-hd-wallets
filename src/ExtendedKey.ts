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
import * as bip32 from 'bip32';
import { BIP32 } from 'bip32';
// internal dependencies
import { KeyEncoding, MACType, Network, NodeEd25519 } from '../index';

const bs58check = require('bs58check');

/**
 * Class `ExtendedKey` describes a hierarchical deterministic extended
 * key that can be derived. This hierarchical deterministic child key
 * derivation feature is described in the Bitcoin BIP32 standard which
 * can be found at following URL:
 *
 *     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
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
  /**
   * Static property to define which type of
   * message authentication code must be used.
   *
   * @var {MACType}
   */
  public static DEFAULT_MAC_TYPE: MACType = MACType.HMAC;

  /**
   * Construct an `ExtendedKey` object out of its' base58 payload.
   *
   * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts
   * @param   node   {BIP32}
   */
  constructor(
    /**
     * The hyper-deterministic node.
     * @var {BIP32 | NodeEd25519}
     */
    public readonly node: BIP32 | NodeEd25519,
    /**
     * The hyper-deterministic node network.
     * @var {Network}
     */
    public network: Network,
    /**
     * The Message Authentication Code type to use.
     * Possible values include HMAC and KMAC.
     * @var {MACType}
     */
    public readonly macType: MACType = MACType.HMAC,
  ) {}

  /**
   * Create an extended key hyper-deterministic node by its' Base58
   * payload.
   *
   * This method uses the `bitcoinjs/bip32` function named `fromBase58`
   * and creates an extended key node by parsing the Base58 binary
   * representation.
   *
   * @param payload
   */
  public static createFromBase58(payload: string, network: Network, macType: MACType = MACType.HMAC): ExtendedKey {
    if (network === Network.SYMBOL) {
      // use NodeEd25519 node implementation

      // interpret payload
      const ed25519Node = NodeEd25519.fromBase58(payload, network);

      // instanciate our ExtendedKey
      return new ExtendedKey(ed25519Node, network, macType);
    }
    // else {
    // use BIP32 node implementation

    // interpret payload
    const bip32Node = bip32.fromBase58(payload);

    // instanciate our ExtendedKey
    return new ExtendedKey(bip32Node, network, macType);
  }

  /**
   * Create an extended key hyper-deterministic node with the master
   * seed.
   *
   * This method uses the `bitcoinjs/bip32` function named `fromSeed`
   * and creates an extended key node by creating HMAC-SHA512 hash
   * of the words 'Bitcoin seed' appended with the `seed` binary
   * representation.
   *
   * The result is split in 2 parts where the left most 32 bytes are
   * the private and right most 32 bytes are the public key.
   *
   * @see https://github.com/bitcoinjs/bip32/blob/master/src/bip32.js#L265
   * @param   seed    {string}
   * @param   network {Network}
   * @return  {ExtendedKey}
   */
  public static createFromSeed(seed: string, network: Network, macType: MACType = MACType.HMAC): ExtendedKey {
    if (network === Network.SYMBOL) {
      // use NodeEd25519 node implementation

      // use hexadecimal seed
      const ed25519Node = NodeEd25519.fromSeed(Buffer.from(seed, 'hex'), network, macType);

      // instantiate our ExtendedKey
      return new ExtendedKey(ed25519Node, network, macType);
    }
    // else {
    // use BIP32 node implementation

    // use hexadecimal seed
    const bip32Node = bip32.fromSeed(Buffer.from(seed, 'hex'));

    // instanciate our ExtendedKey
    return new ExtendedKey(bip32Node, network, macType);
  }

  /**
   * Derive hyper-deterministic node by `path`.
   *
   * Default account layer should derive path `m/44'/43'/0'/0/0`.
   *
   * @see https://github.com/nemtech/NIP/issues/12
   * @param path
   */
  public derivePath(path: string): ExtendedKey {
    // derive path with specialized `derivePath`
    const derived = this.node.derivePath(path);

    if (derived instanceof NodeEd25519) {
      // use NodeEd25519 node implementation
      return new ExtendedKey(derived as NodeEd25519, this.network, this.macType);
    }
    // else {
    // use BIP32 node implementation

    return new ExtendedKey(derived as BIP32, this.network, this.macType);
  }

  /**
   * Return whether an extended key node is neutered or not.
   *
   * Neutered = Public Key only
   * Not Neutered = Private Key available
   *
   * @return {boolean}
   */
  public isNeutered(): boolean {
    // forward to `bitcoinjs/bip32`
    return this.node.isNeutered();
  }

  /**
   * Return whether the current `node` is a master key node or not.
   *
   * @return {boolean}
   */
  public isMaster(): boolean {
    // XXX read parentFingerprint instead of decode
    const base58 = this.node.toBase58();
    const buffer = bs58check.decode(base58);
    const parent = buffer.readUInt32BE(5);

    return parent === 0x00000000;
  }

  /**
   * Get a neutered hyper-deterministic node. This corresponds to
   * a public key only extended key.
   *
   * From a neutered HD-node, users can only generate **public child
   * keys** and no **private child keys**.
   *
   * @see https://github.com/bitcoinjs/bip32/blob/master/ts-src/bip32.ts#L118
   * @return {ExtendedKey}    The neutered HD-node
   */
  public getPublicNode(): ExtendedKey {
    // create new node from neutered
    const node = this.node.neutered();

    if (node instanceof NodeEd25519) {
      // use NodeEd25519 node implementation

      return new ExtendedKey(node as NodeEd25519, this.network, this.macType);
    }
    // else {
    // use BIP32 node implementation

    return new ExtendedKey(node as BIP32, this.network, this.macType);
  }

  /**
   * This method proxies the conversion to base58 format
   * to the `bitcoinjs/bip32` library.
   *
   * @return {string}
   */
  public toBase58(): string {
    // forward to `bitcoinjs/bip32`
    return this.node.toBase58();
  }

  /**
   * Get the private key of the HD-node.
   *
   * This method defaults to returning the hexadecimal notation of
   * the key. Use `KeyEncoding.ENC_BIN` if you need the binary form.
   *
   * @see {KeyEncoding}
   * @return  {string}
   * @throws  {Error}     On use of this method with neutered extended keys (public keys).
   */
  public getPrivateKey(encoding: KeyEncoding = KeyEncoding.ENC_HEX): string | Buffer {
    if (this.isNeutered()) {
      throw new Error('Cannot read private key out of extended public key.');
    }

    // return encoded private key (default hexadecimal format)
    return this.encodeAs(this.node.privateKey, encoding);
  }

  /**
   * Get the public key in hexadecimal notation.
   *
   * This method defaults to returning the hexadecimal notation of
   * the key. Use `KeyEncoding.ENC_BIN` if you need the binary form.
   *
   * @see {KeyEncoding}
   * @return  {string}
   * @throws  {Error}     On use of this method with neutered extended keys (public keys).
   */
  public getPublicKey(encoding: KeyEncoding = KeyEncoding.ENC_HEX): string | Buffer {
    // @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    // ser-p(P) serializes the coordinate and prepends either 0x02 or 0x03 to it.
    // drop first byte for 32-bytes public key
    let publicKey = this.node.publicKey;
    if (this.node.publicKey.byteLength === 33) {
      publicKey = this.node.publicKey.slice(1);
    }

    // return encoded public key (default hexadecimal format)
    return this.encodeAs(publicKey, encoding);
  }

  /**
   * Encode a key into `encoding`. Default `encoding` is `KeyEncoding.ENC_HEX`
   * which results in a hexadecimal notation of the key.
   *
   * @param key
   * @param encoding
   */
  protected encodeAs(key: Buffer, encoding: KeyEncoding = KeyEncoding.ENC_HEX): string | Buffer {
    if (encoding === KeyEncoding.ENC_HEX) {
      // return hexadecimal notation
      return key.toString('hex');
    }

    // return binary Buffer
    return key;
  }
}
