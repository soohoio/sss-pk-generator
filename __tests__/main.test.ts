import { generateKey, privateKeyToAddress, unlockShares } from '../src/main';

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

  const passphraseList = ['a', 'b', 'c', 'd', 'e'];
  const threshold = 3;
  let shares: {
    message: string;
    secret: string;
    cipherparams: string;
  }[] = [];
  let newAddress = 'no_addr';

  it(`generateKey (N=${passphraseList.length}, T=${threshold})`, async () => {
    const res = generateKey(passphraseList, threshold);

    expect(res.address.length).toBe(42);
    expect(res.shares.length).toBe(passphraseList.length);

    console.log(res.shares)

    shares = res.shares;
    newAddress = res.address;
  });

  it('unlockShares', async () => {
    {
      const pk = unlockShares(shares);

      expect(pk.length).toBe(64);
      expect(newAddress).toBe(privateKeyToAddress(pk));
    }

    {
      const pk = unlockShares(shares.slice(0, threshold));

      expect(pk.length).toBe(64);
      expect(newAddress).toBe(privateKeyToAddress(pk));
    }

    {
      let errorHappned = false;
      try {
        const pk = unlockShares(shares.slice(0, threshold - 1));

        expect(pk.length).toBe(64);
        expect(newAddress).toBe(privateKeyToAddress(pk));
      } catch {
        errorHappned = true;
      }

      expect(errorHappned).toBe(true);
    }
  });

  afterAll(() => {
    timeoutSpy.mockRestore();
  });
});
