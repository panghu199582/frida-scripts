const crypto = require('crypto');

const key = "bGfM2l81ekHNq5kv";
const data = {
    "memo": "",
    "transferType": "one-off",
    "bankId": 4,
    "toAccountNumber": "2082934378",
    "amount": "10.00",
    "fromAccountNumber": "1"
};

// 方案1：对 key 进行 Base64
const base64Key = Buffer.from(key).toString('base64');
console.log('Base64 key:', base64Key);

// 方案2：对 body 进行 Base64
const base64Body = Buffer.from(JSON.stringify(data)).toString('base64');
console.log('Base64 body:', base64Body);

// 使用 Base64 后的 key 进行 HMAC
const hmac1 = crypto.createHmac('sha256', base64Key);
hmac1.update(JSON.stringify(data));
const signature1 = hmac1.digest('base64');

// 使用原始 key 对 Base64 后的 body 进行 HMAC
const hmac2 = crypto.createHmac('sha256', key);
hmac2.update(base64Body);
const signature2 = hmac2.digest('base64');

console.log('Signature with Base64 key:', signature1);
console.log('Signature with Base64 body:', signature2);
console.log('Original signature:', 'T8eCKT7f3scVOqbI/ZocC5mW3NLzAF/6K0r1KqJVyxI=');