"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const main_1 = require("../src/main");
describe('sss-pk-generator', () => {
    let timeoutSpy;
    const targetsToDelete = [];
    beforeAll(() => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
        jest.useFakeTimers();
        timeoutSpy = jest.spyOn(global, 'setTimeout');
        jest.runOnlyPendingTimers();
    }));
    const passphraseList = ['a', 'b', 'c', 'd', 'e'];
    const threshold = 3;
    let shares = [];
    let newAddress = 'no_addr';
    it(`generateKey (N=${passphraseList.length}, T=${threshold})`, () => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
        const res = (0, main_1.generateKey)(passphraseList, threshold);
        expect(res.address.length).toBe(42);
        expect(res.shares.length).toBe(passphraseList.length);
        console.log(res.shares);
        shares = res.shares;
        newAddress = res.address;
    }));
    it('unlockShares', () => tslib_1.__awaiter(void 0, void 0, void 0, function* () {
        {
            const pk = (0, main_1.unlockShares)(shares);
            expect(pk.length).toBe(64);
            expect(newAddress).toBe((0, main_1.privateKeyToAddress)(pk));
        }
        {
            const pk = (0, main_1.unlockShares)(shares.slice(0, threshold));
            expect(pk.length).toBe(64);
            expect(newAddress).toBe((0, main_1.privateKeyToAddress)(pk));
        }
        {
            let errorHappned = false;
            try {
                const pk = (0, main_1.unlockShares)(shares.slice(0, threshold - 1));
                expect(pk.length).toBe(64);
                expect(newAddress).toBe((0, main_1.privateKeyToAddress)(pk));
            }
            catch (_a) {
                errorHappned = true;
            }
            expect(errorHappned).toBe(true);
        }
    }));
    afterAll(() => {
        timeoutSpy.mockRestore();
    });
});
//# sourceMappingURL=main.test.js.map