# sss-pk-generator

Private key maker using shamir secret sharing


---
## install

`npm install --save sss-pk-generator`

## basic usages
```javascript
generateKey = (passphraseList: string[], threshold: number)
```

```javascript
unlockShares = (
  pairs: {
    cipherparams: string | { ct: string; iv: string; s: string };
    secret: string;
  }[],
)
```
