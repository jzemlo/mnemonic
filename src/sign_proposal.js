/* eslint-disable no-plusplus */
import {
    generateMnemonic,
    mnemonicToSeedSync
} from "bip39";

import {
    getMasterKeyFromSeed,
    derivePath,
    getPublicKey
} from 'ed25519-hd-key';

import nacl from 'tweetnacl';

import { hexToByte, byteToHex } from './utils';

import { sha256 } from 'js-sha256';

const elliptic = require('elliptic');

function sign(data, key) {
    return byteToHex(nacl.sign.detached(
        Buffer.from(data),
        key.secretKey,
    ));
}

function verify(data, signature, publicKey) {
    return nacl.sign.detached.verify(
        Buffer.from(data),
        hexToByte(signature),
        publicKey,
    );
}


//let mnemonic = generateMnemonic(128);
let mnemonic = "soft soda tornado reject clog speed sheriff option short dress cube skate";
console.log("MNEMONIC: ", mnemonic);

let seed = mnemonicToSeedSync(mnemonic);
console.log('SEED: ', byteToHex(seed));

let masterKey = getMasterKeyFromSeed(seed);

// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
// let masterKey = derivePath("m/44'/11'", seed);

let key = nacl.sign.keyPair.fromSeed(masterKey.key);
console.log('PUBLIC KEY: ', byteToHex(key.publicKey));
console.log('SECRET KEY: ', byteToHex(masterKey.key));

function signProposal(proposalBytes) {

    const digest = sha256.hex(proposalBytes);
    console.log("proposal digest:", digest);

    const eddsa = new elliptic.eddsa('ed25519');
    const signKey = eddsa.keyFromSecret(masterKey.key);
    const sig = eddsa.sign(Buffer.from(digest, 'hex'), signKey);
    console.log("sig hex", sig.toHex());
// now we have the signature, next we should send the signed transaction proposal to the peer
    const signature = Buffer.from(sig.toBytes());
    return {
        signature: signature,
        proposal_bytes: proposalBytes,
    };
}

var proposalBytes = Buffer.from("test proposal");
var singedProposal = signProposal(proposalBytes);
console.log('signedProposal', singedProposal);