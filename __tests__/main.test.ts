import { readFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';
import {
  generateKeyStore,
  privateKeyToAddress,
  unlockKeyStore,
} from '../src/main';

describe('sss-pk-generator', () => {
  let timeoutSpy: jest.SpyInstance;
  const targetsToDelete: {
    address: string;
    n: number;
    t: number;
    path: string;
  }[] = [];

  beforeAll(async () => {
    jest.useFakeTimers();
    timeoutSpy = jest.spyOn(global, 'setTimeout');

    jest.runOnlyPendingTimers();
  });

  it('Make a key store and secret shares', async () => {
    // generate key store file in this directory
    const res = generateKeyStore();
    targetsToDelete.push(res);

    const filename = `keystore-${res.address}.json`;

    const keyJson: {
      address: string;
      ciphertext: string;
    } = JSON.parse(
      readFileSync(resolve(__dirname, '../', filename)).toString(),
    );

    expect(keyJson.address.toLocaleLowerCase().indexOf('0x')).toBe(0);
    expect(keyJson.address.toLocaleLowerCase().length).toBe(42);
    expect(keyJson.ciphertext.length).toBeGreaterThan(0);

    for (let i = 0; i < res.n; i++) {
      const path = resolve(
        __dirname,
        '..',
        `passphrase-shares-${i + 1}-${res.address}.json`,
      );

      const json: {
        passphrase: string;
      } = JSON.parse(readFileSync(path).toString());

      expect(json.passphrase.length).toBeGreaterThan(0);
    }
  });

  it('Could decrypt by the key store and secret shares', async () => {
    const target = targetsToDelete[0];
    const shares: string[] = [];

    for (let i = 0; i < target.n; i++) {
      const path = resolve(
        __dirname,
        '..',
        `passphrase-shares-${i + 1}-${target.address}.json`,
      );

      const json: {
        passphrase: string;
      } = JSON.parse(readFileSync(path).toString());

      shares.push(json.passphrase);
    }

    expect(shares.length).toBe(target.n);

    {
      const pk = unlockKeyStore(target.path, shares);
      expect(privateKeyToAddress(pk)).toBe(target.address);
    }

    {
      const pk = unlockKeyStore(target.path, shares.slice(0, target.t));
      expect(privateKeyToAddress(pk)).toBe(target.address);
    }

    {
      let pk: any = '';
      try {
        pk = unlockKeyStore(target.path, shares.slice(0, target.t - 1));
        privateKeyToAddress(pk);
      } catch {
        pk = 'ERR:catch';
      }
      expect(pk).toBe('ERR:catch');
    }
  });

  afterAll(() => {
    for (const target of targetsToDelete) {
      const filename = `keystore-${target.address}.json`;
      unlinkSync(resolve(__dirname, '../', filename));

      for (let i = 0; i < target.n; i++) {
        unlinkSync(
          resolve(
            __dirname,
            '../',
            `passphrase-shares-${i + 1}-${target.address}.json`,
          ),
        );
      }
    }

    timeoutSpy.mockRestore();
  });
});
