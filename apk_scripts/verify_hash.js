const crypto = require('crypto');

// 1. New Constants from Step 214 Log
const HMAC_KEY_HEX = "c44e1a868f974815c068ce7a26808cb1ac1d1822e250adbf8c47278e77a11e75";
const EXPECTED_HASH = "7fE2qZKwT1opozzhHGkzoU9/Q23JpMctBpcYClBNPYc=";

// 2. The Input Data (Base64 from Arg[0] log)
// This is the Plaintext JSON Body
// 1. 这是你的原始数据对象
const dataObj = {
    "devSeq": 90,
    "clientDeviceID": "a2a04ece-db28-353c-900f-5bc7cb8f56ed",
    "appName": "MOBILE",
    // 注意：这里原本的值是正常的 Base64 字符串（结尾是 ==）
    "devicePubKey": "PFJTQUtleVZhbHVlPjxNb2R1bHVzPndDUGcvRWlobWNOVGk4MnRlSnl3Qmc3SXoxd0owUzVkdlVDYkxodml6bFcwYXIxalF3d3VPRnlsL2pZWWFtQnJjTmlBb0doWkEvWlArbWlUczJiRGhGMFFGZ3I1UmlrUklpcWxmVTNpUUdxTGdFOFpoeWY4QWtzOXBEMGFkSmxVZ21xQlA0VEI2cExENGxBVUkvOUo1elpuTUV0Smh4b05YMTdxTTFERmNuLzFYUkNNL1FKc1N0VENaaUs5akZGOXFZZitvR2h0YUlyN1VLY3o1TnBRNGduQjNsWXAxU3NxZTBESlp6azY3ekQ1Q3BHSC9JS2J0WVZUNXU0MllmY2JnUmlqYnZrN2pxUDJNRE1pQWVsM1ZIeDl4SWtzQzRva1pOQkpYN2xpS0sweFMrTlRWaWZPLzI4Q2ZyRGQrdTliVW9xaVIwLzF1T1pKSVJhUFhnSGdUUT09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==", 
    "deviceName": "Pixel 6a",
    "version": "3.2.9",
    "language": "vi-vn",
    "passWord": "ftrfrcv",
    "uniqueNo": "",
    "username": "09575252",
    "gcmId": "d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg",
    "userID": "09575252",
    "sessionDES": "P3Dg/BLyiTCj/vuVbS9G+IUTBWmpyHygTbRvTTpEtfGFaceMv5Ub5G7KmlcoVu8o2bp3lGOcjcdAhccMafQesWKL+wP3N/UbBTlkaURF+uc0S6bR0C9rfkLGZgpViCZc7OyxwErEpnQeRqLbt2Qko/vhjKKjWBt3SR2umJYDILodqKR3i6H8QYmLvvhFVhHQ1B67g9NA+Ak7vBckTmKivnV6/ouPcmu1qz2lQVl/zEXpMF13BdLdNqQOnxZJKmDpAAMJ6Iam+xk74rcGlmLerMMLJjY9tYPWE58xiUoudFf+bfNdboszXDWtu+/+ZJINSMKBBAZ8qo1wz0+DNZq7Tg==",
    "sms_otp": "",
    "bioPassword": "",
    "login_type": "flexi_app",
    "isRoot": "false",
    "Channel": "MOBILE",
    "encrypt": false,
    "osType": "AND"
};

// 2. 序列化为 JSON 字符串 (无空格)
let jsonString = JSON.stringify(dataObj);

// 3. 【关键步骤】模拟 Gson 的转义行为
// 也就是把 '=' 替换为 '\u003d'，把 '<' 替换为 '\u003c'，把 '>' 替换为 '\u003e'
// 通常最重要的是 =，因为它出现在 Base64 结尾
jsonString = jsonString.replace(/=/g, '\\u003d');
jsonString = jsonString.replace(/</g, '\\u003c');
jsonString = jsonString.replace(/>/g, '\\u003e');

// 验证一下你的源字符串现在长什么样
console.log("修正后的源字符串:", jsonString);
// 应该看到结尾是 \u003d\u003d 而不是 ==

// 4. 转 Base64
const inputBodyBase64 = Buffer.from(jsonString).toString('base64');

console.log("最终 Base64:", inputBodyBase64);

// Arg[1] was a byte array of 32 bytes (SHA-256 size). 
// Base64 from log: "3AxN1FnbznhPJd5kH6nUHkYKcQae53St/rroiy6T8W8="
// This is NOT used in the first hypothesis (Plaintext Body Only), but might be if we fail.
const arg1Base64 = "3AxN1FnbznhPJd5kH6nUHkYKcQae53St/rroiy6T8W8=";

// 3. Test Cases
function runTests() {
    const jsonBody = Buffer.from(inputBodyBase64, 'base64').toString('utf8');
    console.log("JSON Body Length:", jsonBody.length);
    // console.log("JSON Body:", jsonBody);
    
    // Case 1: Just the JSON Body (Arg[0])
    let hmac = crypto.createHmac('sha256', Buffer.from(HMAC_KEY_HEX, 'hex'));
    hmac.update(jsonBody);
    let result = hmac.digest('base64');
    console.log("\n[Case 1] Input = JSON Body Only");
    console.log("Calculated:", result);
    console.log("Expected:  ", EXPECTED_HASH);
    if(result === EXPECTED_HASH) { console.log("✅ MATCH!"); return; }

    // Case 2: Arg[0] + Arg[1] ?
    const arg1Bytes = Buffer.from(arg1Base64, 'base64');
    hmac = crypto.createHmac('sha256', Buffer.from(HMAC_KEY_HEX, 'hex'));
    hmac.update(Buffer.from(jsonBody, 'utf8')); // Body first
    hmac.update(arg1Bytes);                     // Then Arg1
    result = hmac.digest('base64');
    console.log("\n[Case 2] Input = JSON Body + Arg1 (Bytes)");
    console.log("Calculated:", result);
    if(result === EXPECTED_HASH) { console.log("✅ MATCH!"); return; }
    
    // Case 3: Reverse order?
    hmac = crypto.createHmac('sha256', Buffer.from(HMAC_KEY_HEX, 'hex'));
    hmac.update(arg1Bytes);
    hmac.update(Buffer.from(jsonBody, 'utf8'));
    result = hmac.digest('base64');
    console.log("\n[Case 3] Input = Arg1 (Bytes) + JSON Body");
    console.log("Calculated:", result);
    if(result === EXPECTED_HASH) { console.log("✅ MATCH!"); return; }
}

runTests();
