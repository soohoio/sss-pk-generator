"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.privateKeyToAddress = exports.publicKeyToAddress = exports.privateKeyToPublicKey = exports.unlockShares = exports.generateKey = exports.combine = exports.split = void 0;
const CryptoJS = require("crypto-js");
const secrets = require('secrets.js-grempe');
const _privateKeyToPublicKey = require('ethereum-private-key-to-public-key');
const _publicKeyToAddress = require('ethereum-public-key-to-address');
const privateKeyToPublicKey = (privateKey) => {
    return _privateKeyToPublicKey(privateKey).toString('hex');
};
exports.privateKeyToPublicKey = privateKeyToPublicKey;
const publicKeyToAddress = (publicKey) => {
    return _publicKeyToAddress(publicKey);
};
exports.publicKeyToAddress = publicKeyToAddress;
const privateKeyToAddress = (privateKey) => {
    return publicKeyToAddress(privateKeyToPublicKey(privateKey));
};
exports.privateKeyToAddress = privateKeyToAddress;
const _aesJsonFormatter = {
    stringify: (cipherParams) => {
        const jsonObj = {
            ct: cipherParams.ciphertext.toString(CryptoJS.enc.Hex),
        };
        if (cipherParams.iv) {
            jsonObj.iv = cipherParams.iv.toString();
        }
        if (cipherParams.salt) {
            jsonObj.s = cipherParams.salt.toString();
        }
        return JSON.stringify(jsonObj);
    },
    parse: (jsonStr) => {
        const jsonObj = JSON.parse(jsonStr);
        // extract ciphertext from json object, and create cipher params object
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Hex.parse(jsonObj.ct),
        });
        // optionally extract iv or salt
        if (jsonObj.iv) {
            cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
        }
        if (jsonObj.s) {
            cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.s);
        }
        return cipherParams;
    },
};
const _encryptAES = (message, secret) => {
    const res = CryptoJS.AES.encrypt(message, secret, {
        format: _aesJsonFormatter,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });
    return res.toString();
};
const _decryptAES = (cipherParams, secret) => {
    const bytes = CryptoJS.AES.decrypt(typeof cipherParams === 'string'
        ? cipherParams
        : JSON.stringify(cipherParams), secret, {
        format: _aesJsonFormatter,
    });
    return bytes.toString(CryptoJS.enc.Utf8);
};
const split = (secretKey, number, threshold) => {
    const pwHex = secrets.str2hex(secretKey);
    const shares = secrets
        .share(pwHex, number, threshold, 1024)
        .map((s) => s.toString());
    return shares;
};
exports.split = split;
const combine = (shares) => {
    const comb = secrets.combine(shares);
    return secrets.hex2str(comb);
};
exports.combine = combine;
const generateKey = (passphraseList, threshold) => {
    const number = passphraseList.length;
    if (number < threshold || threshold < 1) {
        throw new Error('0 < threshold <= the number of passphrases');
    }
    const newPrivateKey = secrets.random(256);
    const shares = split(newPrivateKey, number, threshold);
    return {
        address: privateKeyToAddress(newPrivateKey),
        shares: shares.map((s, idx) => {
            const res = _encryptAES(s, passphraseList[idx]);
            return {
                message: s,
                secret: passphraseList[idx],
                cipherparams: res,
            };
        }),
    };
};
exports.generateKey = generateKey;
const unlockShares = (pairs) => {
    const shares = pairs.map((p) => _decryptAES(p.cipherparams, p.secret));
    const privateKey = combine(shares);
    return privateKey;
};
exports.unlockShares = unlockShares;
//# sourceMappingURL=main.js.map