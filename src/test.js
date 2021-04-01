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

function sign(data, key) {
    return byteToHex(nacl.sign.detached(
        hexToByte(data),
        key.secretKey,
    ));
}

function verify(data, signature, publicKey) {
    return nacl.sign.detached.verify(
        hexToByte(data),
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
console.log('SECRET KEY: ', byteToHex(key.secretKey));

let message = "test message";
let signature = sign(message, key);

console.log("sign(" + message + ") =", signature);

let validSignature = verify(message, signature, key.publicKey);

console.log("verify(" + message + ", " + signature + ") =", validSignature);