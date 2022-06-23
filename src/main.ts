import * as CryptoJS from 'crypto-js';

const secrets = require('secrets.js-grempe');
const _privateKeyToPublicKey = require('ethereum-private-key-to-public-key');
const _publicKeyToAddress = require('ethereum-public-key-to-address');

const privateKeyToPublicKey = (privateKey: string) => {
  return _privateKeyToPublicKey(privateKey).toString('hex') as string;
};
const publicKeyToAddress = (publicKey: string) => {
  return _publicKeyToAddress(publicKey) as string;
};
const privateKeyToAddress = (privateKey: string) => {
  return publicKeyToAddress(privateKeyToPublicKey(privateKey));
};

const _aesJsonFormatter = {
  stringify: (cipherParams: any) => {
    const jsonObj: any = {
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
  parse: (jsonStr: string) => {
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

const _encryptAES = (message: string, secret: string): string => {
  const res = CryptoJS.AES.encrypt(message, secret, {
    format: _aesJsonFormatter,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  return res.toString();
};

const _decryptAES = (
  cipherParams: string | { ct: string; iv: string; s: string },
  secret: string,
): string => {
  const bytes = CryptoJS.AES.decrypt(
    typeof cipherParams === 'string'
      ? cipherParams
      : JSON.stringify(cipherParams),
    secret,
    {
      format: _aesJsonFormatter,
    },
  );
  return bytes.toString(CryptoJS.enc.Utf8);
};

const split = (
  secretKey: string,
  number: number,
  threshold: number,
): string[] => {
  const pwHex = secrets.str2hex(secretKey);
  const shares = secrets
    .share(pwHex, number, threshold, 1024)
    .map((s) => s.toString());

  return shares;
};
const combine = (shares: string[]): string => {
  const comb = secrets.combine(shares);
  return secrets.hex2str(comb);
};

const generateKey = (
  passphraseList: string[],
  threshold: number,
  privateKey?: string,
) => {
  const number = passphraseList.length;

  if (number < threshold || threshold < 1) {
    throw new Error('0 < threshold <= the number of passphrases');
  }

  const newPrivateKey =
    privateKey && privateKeyToAddress(privateKey)
      ? privateKey
      : secrets.random(256);
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
    }) as {
      message: string;
      secret: string;
      cipherparams: string;
    }[],
  };
};

const unlockShares = (
  pairs: {
    cipherparams: string | { ct: string; iv: string; s: string };
    secret: string;
  }[],
) => {
  const shares = pairs.map((p) => _decryptAES(p.cipherparams, p.secret));

  const privateKey = combine(shares);
  return privateKey;
};

export {
  split,
  combine,
  generateKey,
  unlockShares,
  privateKeyToPublicKey,
  publicKeyToAddress,
  privateKeyToAddress,
};
