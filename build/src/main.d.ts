declare const privateKeyToPublicKey: (privateKey: string) => string;
declare const publicKeyToAddress: (publicKey: string) => string;
declare const privateKeyToAddress: (privateKey: string) => string;
declare const split: (secretKey: string, number: number, threshold: number) => string[];
declare const combine: (shares: string[]) => string;
declare const generateKey: (passphraseList: string[], threshold: number) => {
    address: string;
    shares: {
        message: string;
        secret: string;
        cipherparams: string;
    }[];
};
declare const unlockShares: (pairs: {
    cipherparams: string | {
        ct: string;
        iv: string;
        s: string;
    };
    secret: string;
}[]) => string;
export { split, combine, generateKey, unlockShares, privateKeyToPublicKey, publicKeyToAddress, privateKeyToAddress, };
