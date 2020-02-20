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
import * as bip32 from 'bip32';
import {BIP32} from 'bip32';

// internal dependencies
import {
    CurveAlgorithm,
    ExtendedKey,
    KeyEncoding,
    Network,
    NodeInterface,
    NodeEd25519,
} from "../index";
import { Convert } from "nem2-sdk";

describe('ExtendedKey -->', () => {

    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    const extendedKeys = {
        seedHex: '000102030405060708090a0b0c0d0e0f',
        masterPrv: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
        SHA3: {
            publicKey: '398d57dda0faae646097435e648a2c10f0f367b67e9a1e99a3d9170948d85750',
        },
        KECCAK: {
            publicKey: '398d57dda0faae646097435e648a2c10f0f367b67e9a1e99a3d9170948d85750',
        },
        neutered: [
            {path: 'm', key: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'},
            {path: 'm/0\'', key: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'},
            {path: 'm/0\'/1', key: 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'},
        ],
        nonNeutered: [
            {path: 'm', key: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'},
            {path: 'm/0\'', key: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'},
            {path: 'm/0\'/1', key: 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'},
        ],
    };

    describe('constructor should', () => {

        it('should create BIP32 node object given no network', () => {
            const node = bip32.fromBase58(extendedKeys.neutered[0].key);
            const neuteredMaster = new ExtendedKey(node);

            expect(neuteredMaster.network.curve).to.be.equal(CurveAlgorithm.secp256k1);
        });

        it('should create BIP32 node object given Network.BITCOIN', () => {
            const node = bip32.fromBase58(extendedKeys.neutered[0].key); // using BIP32 implementation
            const neuteredMaster = new ExtendedKey(node, Network.BITCOIN);
            const nodeBIP32 = neuteredMaster.node as BIP32;

            //XXX `BIP32` class cannot be used as a right-hand operator of instanceof
            expect(nodeBIP32).to.not.be.instanceof(NodeEd25519);
            expect(neuteredMaster.network.curve).to.be.equal(CurveAlgorithm.secp256k1);

            // presence checks instead of type check
            expect(node.privateKey).to.not.be.undefined;
            expect(node.publicKey).to.not.be.undefined;
            expect(node.chainCode).to.not.be.undefined;
        });

        it('should create NodeEd25519 node object given Network.CATAPULT', () => {
            const node = NodeEd25519.fromBase58(extendedKeys.neutered[0].key, Network.CATAPULT);
            const neuteredMaster = new ExtendedKey(node, Network.CATAPULT);
            const nodeEd25519 = neuteredMaster.node as NodeEd25519;

            expect(nodeEd25519).to.be.instanceof(NodeEd25519);
            expect(neuteredMaster.network.curve).to.be.equal(CurveAlgorithm.ed25519);
            expect(nodeEd25519.network.curve).to.be.equal(CurveAlgorithm.ed25519);
        });

        it('should create NodeEd25519 node object given Network.CATAPULT_PUBLIC', () => {
            const node = NodeEd25519.fromBase58(extendedKeys.neutered[0].key, Network.CATAPULT_PUBLIC);
            const neuteredMaster = new ExtendedKey(node, Network.CATAPULT_PUBLIC);
            const nodeEd25519 = neuteredMaster.node as NodeEd25519;

            expect(nodeEd25519).to.be.instanceof(NodeEd25519);
            expect(neuteredMaster.network.curve).to.be.equal(CurveAlgorithm.ed25519);
            expect(nodeEd25519.network.curve).to.be.equal(CurveAlgorithm.ed25519);
        });

        it('create master key with payload for "m" path', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[0].key));
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[0].key));

            expect(neuteredMaster.isMaster()).to.be.equal(true);
            expect(nonNeuteredMaster.isMaster()).to.be.equal(true);
        });

        it('create child key with payload for "m/0" path', () => {
            const neuteredChild = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
            const nonNeuteredChild = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[1].key));

            expect(neuteredChild.isMaster()).to.be.equal(false);
            expect(nonNeuteredChild.isMaster()).to.be.equal(false);
        });

        it('create neutered from neutered keys', () => {
            extendedKeys.neutered.map(
                (neuteredKey) => {
                    const neuteredNode = new ExtendedKey(bip32.fromBase58(neuteredKey.key));
                    expect(neuteredNode.isNeutered()).to.be.equal(true);
                });
        });

        it('create non-neutered from non-neutered keys', () => {
            extendedKeys.nonNeutered.map(
                (nonNeuteredKey) => {
                    const nonNeuteredNode = new ExtendedKey(bip32.fromBase58(nonNeuteredKey.key));
                    expect(nonNeuteredNode.isNeutered()).to.be.equal(false);
                });
        });
    });

    describe('createFromBase58 should', () => {

        it('use network Network.BITCOIN given no network', () => {
            const neuteredNode = ExtendedKey.createFromBase58(extendedKeys.neutered[0].key);

            // check that Network.BITCOIN is default
            expect(neuteredNode.network.privateKeyPrefix).to.be.equal(Network.BITCOIN.privateKeyPrefix);
            expect(neuteredNode.network.publicKeyPrefix).to.be.equal(Network.BITCOIN.publicKeyPrefix);
            expect(neuteredNode.network.curve).to.be.equal(CurveAlgorithm.secp256k1);
        });

        it('use network given network Network.CATAPULT', () => {
            const neuteredNode = ExtendedKey.createFromBase58(extendedKeys.neutered[0].key, Network.CATAPULT);

            // check that Network.CATAPULT was used correctly
            expect(neuteredNode.network.privateKeyPrefix).to.be.equal(Network.CATAPULT.privateKeyPrefix);
            expect(neuteredNode.network.publicKeyPrefix).to.be.equal(Network.CATAPULT.publicKeyPrefix);
            expect(neuteredNode.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // also check node implementation that was used
            expect(neuteredNode.node).to.be.instanceof(NodeEd25519);
        });

        it('use network given network Network.CATAPULT_PUBLIC', () => {
            const neuteredNode = ExtendedKey.createFromBase58(extendedKeys.neutered[0].key, Network.CATAPULT_PUBLIC);

            // check that Network.CATAPULT was used correctly
            expect(neuteredNode.network.privateKeyPrefix).to.be.equal(Network.CATAPULT_PUBLIC.privateKeyPrefix);
            expect(neuteredNode.network.publicKeyPrefix).to.be.equal(Network.CATAPULT_PUBLIC.publicKeyPrefix);
            expect(neuteredNode.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // also check node implementation that was used
            expect(neuteredNode.node).to.be.instanceof(NodeEd25519);
        });

        it('create neutered from extended public key', () => {
            const neuteredNode = ExtendedKey.createFromBase58(extendedKeys.neutered[0].key);
            expect(neuteredNode.isNeutered()).to.be.equal(true);
        });

        it('create non-neutered from extended private key', () => {
            const nonNeuteredNode = ExtendedKey.createFromBase58(extendedKeys.nonNeutered[0].key);
            expect(nonNeuteredNode.isNeutered()).to.be.equal(false);
        });
    });

    describe('createFromSeed should', () => {
        it('create master key with hexadecimal seed notation', () => {
            const masterFromSeed = ExtendedKey.createFromSeed(extendedKeys.seedHex);
            expect(masterFromSeed.isMaster()).to.be.equal(true);

            // check XPUB and XPRV
            expect(masterFromSeed.getPublicNode().toBase58()).to.be.equals(extendedKeys.neutered[0].key);
            expect(masterFromSeed.toBase58()).to.be.equals(extendedKeys.nonNeutered[0].key);
        });

        it('use network Network.BITCOIN given no network', () => {
            const masterFromSeed = ExtendedKey.createFromSeed(extendedKeys.seedHex);

            // check that Network.BITCOIN is default
            expect(masterFromSeed.network.privateKeyPrefix).to.be.equal(Network.BITCOIN.privateKeyPrefix);
            expect(masterFromSeed.network.publicKeyPrefix).to.be.equal(Network.BITCOIN.publicKeyPrefix);
            expect(masterFromSeed.network.curve).to.be.equal(CurveAlgorithm.secp256k1);
        });

        it('use network given network Network.CATAPULT', () => {
            const masterFromSeed = ExtendedKey.createFromSeed(extendedKeys.seedHex, Network.CATAPULT);

            // check that Network.CATAPULT was used correctly
            expect(masterFromSeed.network.privateKeyPrefix).to.be.equal(Network.CATAPULT.privateKeyPrefix);
            expect(masterFromSeed.network.publicKeyPrefix).to.be.equal(Network.CATAPULT.publicKeyPrefix);
            expect(masterFromSeed.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // also check node implementation that was used
            expect(masterFromSeed.node).to.be.instanceof(NodeEd25519);
        });

        it('use network given network Network.CATAPULT_PUBLIC', () => {
            const masterFromSeed = ExtendedKey.createFromSeed(extendedKeys.seedHex, Network.CATAPULT_PUBLIC);

            // check that Network.CATAPULT was used correctly
            expect(masterFromSeed.network.privateKeyPrefix).to.be.equal(Network.CATAPULT_PUBLIC.privateKeyPrefix);
            expect(masterFromSeed.network.publicKeyPrefix).to.be.equal(Network.CATAPULT_PUBLIC.publicKeyPrefix);
            expect(masterFromSeed.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // also check node implementation that was used
            expect(masterFromSeed.node).to.be.instanceof(NodeEd25519);
        });
    });

    describe('getPublicNode() should', () => {
        it('create neutered from non-neutered', () => {
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[0].key));
            const publicNode = nonNeuteredMaster.getPublicNode();

            expect(publicNode.isNeutered()).to.be.equal(true);
        });

        it('create neutered from neutered', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicNode = neuteredMaster.getPublicNode();

            expect(publicNode.isNeutered()).to.be.equal(true);
        });

        it('use correct network after being neutered', () => {
            const node = NodeEd25519.fromBase58(extendedKeys.neutered[1].key);
            const neuteredMaster = new ExtendedKey(node, Network.CATAPULT);
            const publicNode = neuteredMaster.getPublicNode();

            // check that Network.CATAPULT was used correctly
            expect(publicNode.network.privateKeyPrefix).to.be.equal(Network.CATAPULT.privateKeyPrefix);
            expect(publicNode.network.publicKeyPrefix).to.be.equal(Network.CATAPULT.publicKeyPrefix);
            expect(publicNode.network.curve).to.be.equal(CurveAlgorithm.ed25519);

            // also check node implementation that was used
            expect(publicNode.node).to.be.instanceof(NodeEd25519);
        });
    });

    describe('toBase58() should', () => {
        it('produce same payloads', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const neuteredBase58 = neuteredMaster.toBase58();
            const nonNeuteredBase58 = nonNeuteredMaster.toBase58();

            expect(neuteredBase58).to.be.equal(extendedKeys.neutered[1].key);
            expect(nonNeuteredBase58).to.be.equal(extendedKeys.nonNeutered[1].key);
        });
    });

    describe('getPrivateKey() should', () => {
        it('throw error with neutered nodes', () => {
            expect((function () {
                const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
                const privateKey = neuteredMaster.getPrivateKey();
            })).to.throw('Cannot read private key out of extended public key.');
        });

        it('return hexadecimal notation by default', () => {
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const privateKey = nonNeuteredMaster.getPrivateKey();

            expect(privateKey.length).to.be.equal(64);
            expect(privateKey).to.be.equal('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea');
        });

        it('return binary notation with ENC_BIN', () => {
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[1].key));
            const privateKey: Buffer = nonNeuteredMaster.getPrivateKey(KeyEncoding.ENC_BIN) as Buffer;
            const uintArray = new Uint8Array(privateKey);

            const expectedBytes = [
                237, 178, 225,  79,
                158, 231, 125,  38,
                221, 147, 180, 236,
                237, 232, 209, 110,
                212,   8, 206,  20,
                155, 108, 216,  11,
                  7,  21, 162, 217,
                 17, 160, 175, 234
            ]

            expect(privateKey).to.be.instanceof(Buffer);
            expect(privateKey.byteLength).to.be.equal(32);
            expect(uintArray.length).to.be.equal(32);
            expect(Array.from(uintArray)).to.be.deep.equal(expectedBytes);
        });
    });

    describe('getPublicKey() should', () => {
        it('return public key for both neutered and non-neutered', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[0].key));
            const nonNeuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.nonNeutered[0].key));
            const neuteredPubKey = neuteredMaster.getPublicKey();
            const nonNeuteredPubKey = nonNeuteredMaster.getPublicKey();

            expect(neuteredPubKey.length).to.be.equal(64);
            expect(nonNeuteredPubKey.length).to.be.equal(64);
        });

        it('return hexadecimal notation by default', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicKey = neuteredMaster.getPublicKey();

            expect(publicKey.length).to.be.equal(64);
            expect(publicKey).to.be.equal('5a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56');
        });

        it('return binary notation with ENC_BIN', () => {
            const neuteredMaster = new ExtendedKey(bip32.fromBase58(extendedKeys.neutered[1].key));
            const publicKey: Buffer = neuteredMaster.getPublicKey(KeyEncoding.ENC_BIN) as Buffer;
            const uintArray = new Uint8Array(publicKey);

            const expectedBytes = [
                 90, 120,  70,  98,
                164, 162,  10, 101,
                191, 106, 171, 154,
                233, 138, 108,   6,
                138, 129, 197,  46,
                 75,   3,  44,  15,
                181,  64,  12, 112,
                108, 252, 204,  86
            ];

            expect(publicKey).to.be.instanceof(Buffer);
            expect(publicKey.byteLength).to.be.equal(32);
            expect(uintArray.length).to.be.equal(32);
            expect(Array.from(uintArray)).to.be.deep.equal(expectedBytes);
        });

        // http://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=blob;f=tests/t-ed25519.inp
        // - extracted vectors: #1, #2, #3, #166, #218, #219. #220, #337, #500, #501
        const vectorED25519 = [
            {sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
             pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'},
            {sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
             pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'},
            {sk: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
             pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'},
            {sk: '3558d3a74395bdcba560e2c45a91960cec6cb3edbcd30e722f7f055210f37b51',
             pk: '534f43eba403a84f25967c152d93a0175ec8293e6f4375319eadf957401fbbd2'},
            {sk: 'bfbcd867027a199978d53e359d70318fc78c7cc7bb5c7996ba797c8554f3f0f0',
             pk: '7c5ae3bab9201199dfbe74b7d1ec157125bdbaa4520f501da3f248579dc6c22d'},
            {sk: 'df2df8a9d66d5638cdee09324e7b10f8ed29ab91387e3147b7dc03f7cd800508',
             pk: '5c042e157fb7fb12d4d4fef2847141ecfb57c1253e14eaf3004d6513f52fe625'},
            {sk: 'e8ee065f9907f1efa2daecb23a0425f353094da02bc2c931f0a587efc0d13de1',
             pk: 'c72651b7fb7ac0337a172977496fd7f2a72aea889385835e563c6b6053a32dc1'},
            {sk: 'c57a43dcd7bab8516009546918d71ad459b7345efdca8d4f19929875c839d722',
             pk: '2083b444236b9ab31d4e00c89d55c6260fee71ac1a47c4b5ba227404d382b82d'},
            {sk: 'afcecea92439e44a43ed61b673043dcbc4e360f2f30cd07896cda20cb988d4e3',
             pk: 'd231f69235a2e3a1dd5f6c2a9aaf20c03454b9a29f4e3a29ab94689d0d723e50'},
            {sk: 'b834c6e0facbff580dd3b23753959a4c2154c219521b3d27035d071f6599bd02',
             pk: 'd1c384715e3b3d02c13e090605534c7db740da2aa560f53200a3ced8beae8cf8'},
        ]
        it('produce SHA512 ED25519 compliant public key', () => {
            // http://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=blob;f=tests/t-ed25519.inp
            vectorED25519.map(vec => {
                const privateKey = Buffer.from(Convert.hexToUint8(vec.sk));
                const bip32Node = new NodeEd25519(privateKey, undefined, Buffer.from(''), Network.CATAPULT);

                expect(bip32Node.privateKey.toString('hex')).to.be.equal(vec.sk);
                expect(bip32Node.publicKey.toString('hex')).to.be.equal(vec.pk);
            })
        })

        it('produce SHA512 public key given Network.CATAPULT', () => {
            const privateHex = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPub = '2e834140fd66cf87b254a693a2c7862c819217b676d3943267156625e816ec6f';
            const privateKey = Buffer.from(Convert.hexToUint8(privateHex));
            const bip32Node = new NodeEd25519(privateKey, undefined, Buffer.from(''), Network.CATAPULT);

            expect(bip32Node.privateKey.toString('hex')).to.be.equal(privateHex);
            expect(bip32Node.publicKey.toString('hex')).to.be.equal(expectPub);
        });

        it('produce correct SHA512 public key given REVERSED private key', () => {
            const privateHex = '575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced';
            const expectPub = '5112ba143b78132af616af1a94e911ead890fdb51b164a1b57c352ecd9ca1894';

            // NIS compatibility requires "key reversal".
            const reversedKey = Buffer.from(Convert.hexToUint8Reverse(privateHex));
            const bip32Node = new NodeEd25519(reversedKey, undefined, Buffer.from(''), Network.CATAPULT_PUBLIC);

            expect(bip32Node.privateKey.toString('hex')).to.be.equal(reversedKey.toString('hex'));
            expect(bip32Node.publicKey.toString('hex')).to.be.equal(expectPub);
        });
    });

    describe('derivePath() should', () => {
        it('derive first chain with path "m/0\'"', () => {
            const masterKey = ExtendedKey.createFromSeed(extendedKeys.seedHex);
            const fstChainNode = masterKey.derivePath("m/0'");
            expect(fstChainNode.isMaster()).to.be.equal(false);

            // check XPUB and XPRV
            expect(fstChainNode.getPublicNode().toBase58()).to.be.equals(extendedKeys.neutered[1].key);
            expect(fstChainNode.toBase58()).to.be.equals(extendedKeys.nonNeutered[1].key);
        });

        it('derive child chain with path "m/0\'/1"', () => {
            const masterKey = ExtendedKey.createFromSeed(extendedKeys.seedHex);
            const childChainNode = masterKey.derivePath("m/0'/1");
            expect(childChainNode.isMaster()).to.be.equal(false);

            // check XPUB and XPRV
            expect(childChainNode.getPublicNode().toBase58()).to.be.equals(extendedKeys.neutered[2].key);
            expect(childChainNode.toBase58()).to.be.equals(extendedKeys.nonNeutered[2].key);
        });
    });

});
