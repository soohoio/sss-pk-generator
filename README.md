# sss-pk-generator

shamir secret sharing을 이용한 private key maker


---
## 설치

`npm install --save sss-pk-generator`

## 기본 사용법
### key store 파일과 secret shares 만들기

```javascript
import { generateKeyStore } from 'sss-pk-generator';

// 경로를 지정하지 않으면 프로젝트 root 폴더에 key store가 생성됨
// N = 5
// T = 3
generateKeyStore();
```
### key store 파일과 secret shares를 이용하여 Private Key 얻기
```javascript
import { unlockKeyStore } from 'sss-pk-generator';

// keystore가 존재하는 path를 입력하면 privateKey를 얻을 수 있음
const privateKey = unlockKeyStore(
  '/Users/Myproject/keystore-0x5D409F24446FA708e9D51EA8524dAaF12C84Ac6B.json',
);

console.log(privateKey);
```