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

import { composePrivateKey } from 'crypto-key-composer';

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


const privKey = { format: 'pkcs8-pem',
    keyAlgorithm: { id: 'ed25519' },
    keyData: {
    seed: masterKey.key
    },
    encryptionAlgorithm: null
};

var keyPEM = composePrivateKey(privKey);

console.log("PEM encoded private key");
console.log(keyPEM);

var cert_fields = "/C=PL/CN=user1@example.com";

var spawn = require('child_process').spawn,
    child = spawn("openssl", ["req", "-nodes", "-new", "-key", "-", "-keyout", "-", "-out", "-", "-subj", cert_fields]);

var csr = '';
child.stdout.on('data', function(data) {
    csr += data.toString();
});
child.on('close', function(code) {
    console.log("CSR", cert_fields);
    console.log(csr);
});

child.stdin.setEncoding('utf-8');

child.stdin.write(keyPEM);

child.stdin.end();

