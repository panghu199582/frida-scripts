/*
 * Pgbank Encryption Generator
 * 
 * Logic Verified from Runtime Logs:
 * 1. AES Key: 32 Random Bytes.
 * 2. sessionDES: RSA_Encrypt( Base64( AES_Key ) ) using PKCS1Padding.
 *    - Input: The Base64 string of the AES key.
 *    - Output: Base64 string of the encrypted data.
 *    - Key: Standard X.509 RSAPublicKey (PEM format detected in logs).
 * 3. reqBody: AES-256-CBC( Plaintext_JSON, Key=AES_Key, IV=Random )
 *    - Plaintext: Gson formatted JSON (escaped =, <, >, etc).
 *    - Output: Base64( IV + Ciphertext ).
 * 4. hashReqBody: HMAC-SHA256( Key=AES_Key_Bytes, Data=Plaintext_JSON ).
 */

const crypto = require('crypto');
const forge = require('node-forge');

// --- Configuration ---

// SERVER Public Key (X.509 Format from Log)
// Used for RSA Encryption of Session Key
const SERVER_PUB_KEY_X509_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8ynQBVRc+BQeqgjCT2Nz9T6g/1pbSzbRDA1n10eVEjTjbq566fBCAHmV+DwRx6mJE1baOdDx1nUDZXD9Dkh5qvPyVbG+7Xl5KFKzkTCy9zfnlSJqcLb628hrxfuK2lZkd7PrxcmFiNl8qBZdanGHEyT6McNnGeKoEBQLfuw2c8EG4foVaMUNg6zt+VhzxTkLoNb51XSCMS6wzlTxCJsbEPb0GqBvsmxiU6AVrYNWdfu8K8ZzYHZUQ+/y6BOfLqFMkJgyzRiPSELnVb7Y6d5wG1nKef9vASMPPG6aI4M/Ioym2Mk5HNgYDFYJSrxQX8bQ++sERVCnmHdZzaWNBjaEawIDAQAB";

// CLIENT Public Key (Sent in payload)
const CLIENT_PUB_KEY_B64 = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnVIN0wveVlyeFg1UUZ4MUN3dDNDQ2k3UktoTnBlbjJrUFVtT0xrNGxMM3N5N2pmaEdYTVpsRURISXNwWVBlek5TelRoN1gwaW5BUFdjQWZSSnJaZ2hidTBDNGVYaXo3ekh1MllhdVVydDYxdEVGTk9GNXlvWURmM0lBLzZpaXEyb1ZxNktrVnVLSW5PenZoNURrdGhpTFZmbDVaZ0NwditJQzlFM3JsSEpQckg5UVprZTVMTnBjZEs5YlVEbmhTRDV3MjFxUVY3YXBkU29RNkMwQU1vbGVjMHQ0VmZ0ZGFPS3FYczVvUG91Um5pQjdLZlpTOU5MUllHUk5PVHI5MWlVWEFkcnRCK3l1MExBMkdwWWR4bEcxM0hVY05qZGFUYm1YeEFzOXJPY0NHOUF1N01YRjRsVXBPZGFTSnp5ZG1tZGQ2VGdKKytXU1BVbE5hZHlvalBJdz09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==";


// --- Helpers ---

/**
 * Generate sessionDES (RSA Encryption)
 * Logic: Encrypt basic string representation of AES key
 */
function encryptSessionKeyRSA(aesKeyBytes, x509KeyB64) {
    // 1. Construct PEM string from X.509 Base64
    const pem = "-----BEGIN PUBLIC KEY-----\n" + 
                x509KeyB64.match(/.{1,64}/g).join('\n') + 
                "\n-----END PUBLIC KEY-----";

    // 2. Parse Public Key
    const publicKey = forge.pki.publicKeyFromPem(pem);

    // 3. Encrypt AES Key String
    // Logic: Transform raw bytes -> Base64 String -> RSA Encrypt
    const aesKeyB64Str = aesKeyBytes.toString('base64');
    
    // Encrypt using PKCS#1 v1.5 padding (standard)
    const encrypted = publicKey.encrypt(aesKeyB64Str, 'RSAES-PKCS1-V1_5');

    // 4. Return Base64 of the Ciphertext
    return Buffer.from(encrypted, 'binary').toString('base64');
}

/**
 * AES Encryption for reqBody
 * Rule: AES_CBC_PKCS7( Plaintext, Key, IV )
 * Format: Base64( IV + Ciphertext )
 */
function encryptBodyAES(plaintext, keyBytes) {
    // Generate Random IV (16 bytes)
    const iv = crypto.randomBytes(16);
    
    // Create Cipher (AES-256-CBC, PKCS7 padding default)
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBytes, iv);
    
    // Encrypt
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Combine IV + Ciphertext and return Base64
    return Buffer.concat([iv, encrypted]).toString('base64');
}

/**
 * Gson-style Stringify
 * HTML escapes equal signs, brackets, etc.
 */
function gsonStringify(obj) {
    return JSON.stringify(obj)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/=/g, '\\u003d')
        .replace(/&/g, '\\u0026')
        .replace(/'/g, '\\u0027');
}

// --- Main Payload Generator ---
function createRealisticPayload() {
    // 1. Generate Random AES Session Key (32 bytes)
    const sessionKeyBytes = crypto.randomBytes(32);
    // console.log("AES Key (B64): " + sessionKeyBytes.toString('base64'));
    
    // 2. Encrypt Session Key with RSA (to get sessionDES)
    const sessionDES = encryptSessionKeyRSA(sessionKeyBytes, SERVER_PUB_KEY_X509_B64);

    // 3. Prepare Plaintext Request Body
    // Using verified values from trace
    const baseBody = {
        "devSeq": 90,
        "clientDeviceID": "a2a04ece-db28-353c-900f-5bc7cb8f56ed",
        "appName": "MOBILE",
        "devicePubKey": CLIENT_PUB_KEY_B64,
        "deviceName": "Pixel 6a",
        "version": "3.2.9",
        "language": "vi-vn",
        "passWord": "ftrfrcv", 
        "uniqueNo": "",
        "username": "09575252", 
        "gcmId": "d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg",
        "userID": "09575252",
        "sessionDES": sessionDES,
        "sms_otp": "",
        "bioPassword": "",
        "login_type": "flexi_app",
        "isRoot": "false",
        "Channel": "MOBILE",
        "encrypt": false,
        "osType": "AND"
    };

    // 4. Stringify Body (Gson Format)
    const finalPlainBodyStr = gsonStringify(baseBody);
    
    // 5. Calculate HMAC (hashReqBody)
    // Key: AES Session Key Bytes
    // Data: Plaintext Gson Body String
    const hashReqBody = crypto.createHmac('sha256', sessionKeyBytes)
        .update(finalPlainBodyStr)
        .digest('base64');

    // 6. Encrypt Body (reqBody)
    // Key: AES Session Key Bytes
    // Data: Plaintext Gson Body String
    const reqBodyBase64 = encryptBodyAES(finalPlainBodyStr, sessionKeyBytes);

    // 7. Prepare Header
    const requestHeader = {
        "osType": "AND",
        "TranSeq": Math.floor(Math.random() * 90000000 + 10000000).toString(),
        "trandate": new Date().toLocaleString('en-GB').replace(',', ''),
        "encrypt": false,
        "ErrorCode": 0,
        "appName": "PGBankMobile",
        "gcmId": baseBody.gcmId,
        "devSeq": "1", 
        "version": "3.2.9",
        "language": "vi-vn",
        "hashReqBody": hashReqBody, // IMPORTANT: Hash is included in Header
        "isRoot": "false",
        "IpAddress": "103.63.114.42",
        "UniqueDeviceId": baseBody.clientDeviceID,
        "isNfcAvailable": "Y"
    };
    const requestHeaderStr = JSON.stringify(requestHeader);

    // 8. Return Final Payload Object
    return {
        "requestHeader": requestHeaderStr,
        "hashReqBody": hashReqBody,
        "language": "vi-vn",
        "ReqBody": reqBodyBase64,
        "osType": "AND",
        "devicePubKey": CLIENT_PUB_KEY_B64,
        "sessionDES": sessionDES
    };
}

// Run (Uncomment to execute)
const payload = createRealisticPayload();
console.log(JSON.stringify(payload, null, 2));
