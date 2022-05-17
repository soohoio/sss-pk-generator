import { resolve } from 'path';
import { readFileSync, writeFileSync } from 'fs';
import * as CryptoJS from 'crypto-js';
import { cwd } from 'process';

const secrets = require('secrets.js-grempe');
const _privateKeyToPublicKey = require('ethereum-private-key-to-public-key');
const _publicKeyToAddress = require('ethereum-public-key-to-address');

const _jsonKeyStringBuilder = (address: string, ciphertext: string) => {
  return `{
  "address": "${address}",
  "ciphertext": "${ciphertext}"
}`;
};

const _makeNodeJsonFile = (path: string, text: string) => {
  writeFileSync(path, text);
};

const privateKeyToPublicKey = (privateKey: string) => {
  return _privateKeyToPublicKey(privateKey).toString('hex') as string;
};
const publicKeyToAddress = (publicKey: string) => {
  return _publicKeyToAddress(publicKey) as string;
};
const privateKeyToAddress = (privateKey: string) => {
  return publicKeyToAddress(privateKeyToPublicKey(privateKey));
};

const _encryptAES = (privateKey: string, secret: string): string => {
  return CryptoJS.AES.encrypt(privateKey, secret).toString();
};

const _decryptAES = (ciphertext: string, secret: string): string => {
  const bytes = CryptoJS.AES.decrypt(ciphertext, secret);
  return bytes.toString(CryptoJS.enc.Utf8);
};

const split = (
  secretKey: string,
  number: number,
  threshold: number,
): string[] => {
  const pwHex = secrets.str2hex(secretKey);
  const shares = secrets.share(pwHex, number, threshold);

  return shares;
};
const combine = (shares: string[]): string => {
  const comb = secrets.combine(shares);
  return secrets.hex2str(comb);
};

const generateKey = (
  passphraseLength: number,
  number: number,
  threshold: number,
) => {
  // make new random passphrase
  const passphrase: string = secrets.random(passphraseLength * 4);
  // divide passphrase into 3/5
  const newPrivateKey = secrets.random(256);

  // START OF key store contents
  const address = privateKeyToAddress(newPrivateKey);
  const ciphertext = _encryptAES(newPrivateKey, passphrase);
  // END OF key store contents

  const shares = split(passphrase, number, threshold);

  return {
    address,
    ciphertext,
    shares,
  };
};

const unlockShares = (ciphertext: string, shares: string[]) => {
  const passphrase = combine(shares);
  return _decryptAES(ciphertext, passphrase);
};

const generateKeyStore = (dir = './') => {
  const passphraseLength = 31;
  const numberOfShares = 5;
  const threshold = 3;

  const res = generateKey(passphraseLength, numberOfShares, threshold);

  const filename = `keystore-${res.address}.json`;
  const path = resolve(cwd(), dir, filename);
  const keystoreJson = _jsonKeyStringBuilder(res.address, res.ciphertext);

  _makeNodeJsonFile(path, keystoreJson);

  for (let i = 0; i < res.shares.length; i++) {
    _makeNodeJsonFile(
      resolve(cwd(), dir, `passphrase-shares-${i + 1}-${res.address}.json`),
      `{
  "passphrase": "${res.shares[i]}"
}`,
    );
  }

  return {
    address: res.address,
    n: numberOfShares,
    t: threshold,
    path,
  };
};

const unlockKeyStore = (keystorePath: string, shares: string[]) => {
  const fileContent = readFileSync(keystorePath).toString();
  const keyJson: {
    address: string;
    ciphertext: string;
  } = JSON.parse(fileContent);

  return unlockShares(keyJson.ciphertext, shares);
};

export {
  split,
  combine,
  generateKey,
  unlockShares,
  privateKeyToPublicKey,
  publicKeyToAddress,
  privateKeyToAddress,
  generateKeyStore,
  unlockKeyStore,
};
