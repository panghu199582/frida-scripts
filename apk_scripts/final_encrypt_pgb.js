/*
 * Pgbank Final Encryption Generator
 * Based on Runtime Hooks:
 * 1. AES Key: 32 Random Bytes.
 * 2. sessionDES: RSA_Encrypt( Base64( AES_Key ) )
 * 3. reqBody: AES-256-CBC( Plaintext_JSON, Key=AES_Key, IV=Random ) -> [IV][Cipher]
 * 4. hashReqBody: HMAC( Header + ReqBodyB64 )
 */
const crypto = require('crypto');
const forge = require('node-forge');

// --- Configuration ---
// SERVER Public Key (Verified from logs to be used for RSA Encryption)
const SERVER_PUB_KEY_B64 = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjh5blFCVlJjK0JRZXFnakNUMk56OVQ2Zy8xcGJTemJSREExbjEwZVZFalRqYnE1NjZmQkNBSG1WK0R3Ung2bUpFMWJhT2REeDFuVURaWEQ5RGtoNXF2UHlWYkcrN1hsNUtGS3prVEN5OXpmbmxTSnFjTGI2MjhocnhmdUsybFprZDdQcnhjbUZpTmw4cUJaZGFuR0hFeVQ2TWNObkdlS29FQlFMZnV3MmM4RUc0Zm9WYU1VTmc2enQrVmh6eFRrTG9OYjUxWFNDTVM2d3psVHhDSnNiRVBiMEdxQnZzbXhpVTZBVnJZTldkZnU4SzhaellIWlVRKy95NkJPZkxxRk1rSmd5elJpUFNFTG5WYjdZNmQ1d0cxbktlZjl2QVNNUFBHNmFJNE0vSW95bTJNazVITmdZREZZSlNyeFFYOGJRKytzRVJWQ25tSGRaemFXTkJqYUVhdz09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==";

// CLIENT Public Key (Sent in payload)
const CLIENT_PUB_KEY_B64 = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnVIN0wveVlyeFg1UUZ4MUN3dDNDQ2k3UktoTnBlbjJrUFVtT0xrNGxMM3N5N2pmaEdYTVpsRURISXNwWVBlek5TelRoN1gwaW5BUFdjQWZSSnJaZ2hidTBDNGVYaXo3ekh1MllhdVVydDYxdEVGTk9GNXlvWURmM0lBLzZpaXEyb1ZxNktrVnVLSW5PenZoNURrdGhpTFZmbDVaZ0NwditJQzlFM3JsSEpQckg5UVprZTVMTnBjZEs5YlVEbmhTRDV3MjFxUVY3YXBkU29RNkMwQU1vbGVjMHQ0VmZ0ZGFPS3FYczVvUG91Um5pQjdLZlpTOU5MUllHUk5PVHI5MWlVWEFkcnRCK3l1MExBMkdwWWR4bEcxM0hVY05qZGFUYm1YeEFzOXJPY0NHOUF1N01YRjRsVXBPZGFTSnp5ZG1tZGQ2VGdKKytXU1BVbE5hZHlvalBJdz09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==";


// --- Helpers ---

function getRealXmlFromB64(b64) {
    return Buffer.from(b64, 'base64').toString('utf8');
}

function encryptSessionKeyRSA(aesKeyBytes, xmlKey) {
    // console.log("DEBUG XML:\n" + xmlKey); 
    // 1. Parse XML Components
    const modulusMatch = xmlKey.match(/<Modulus>([\s\S]*?)<\/Modulus>/);
    const exponentMatch = xmlKey.match(/<Exponent>([\s\S]*?)<\/Exponent>/);
    if (!modulusMatch || !exponentMatch) throw new Error("Invalid RSA XML");

    const modB64 = modulusMatch[1];
    const expB64 = exponentMatch[1];

    // 2. Decode Base64 to Hex for BigInteger
    const modHex = forge.util.createBuffer(forge.util.decode64(modB64)).toHex();
    const expHex = forge.util.createBuffer(forge.util.decode64(expB64)).toHex();

    // 3. Create Key Object Directly
    const publicKey = forge.pki.setRsaPublicKey(
        new forge.jsbn.BigInteger(modHex, 16),
        new forge.jsbn.BigInteger(expHex, 16)
    );

    // 4. Encrypt AES Key String (Double Base64 Logic)
    // Rule: RSA_Encrypt( Base64_String_Of_AES_Key )
    const aesKeyB64Str = aesKeyBytes.toString('base64');
    
    // Use raw binary string for 'forge' encrypt input if needed, but strings work fine usually.
    const encrypted = publicKey.encrypt(aesKeyB64Str, 'RSAES-PKCS1-V1_5');

    // 5. Return Base64 of the RSA ciphertext
    return Buffer.from(encrypted, 'binary').toString('base64');
}

/**
 * AES Encryption for reqBody
 * Rule: AES_CBC_PKCS7( Plaintext, Key, IV )
 * Format: Base64( IV + Ciphertext )
 */
function encryptBodyAES(plaintext, keyBytes) {
    // Generate Random IV
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBytes, iv);
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Combine IV + Ciphertext
    const combined = Buffer.concat([iv, encrypted]);
    return combined.toString('base64');
}

function signRequest(headerJson, bodyBase64) {
    const input = headerJson + bodyBase64;
    const hmac = crypto.createHmac('sha256', Buffer.from(HMAC_KEY_HEX, 'hex'));
    hmac.update(input);
    return hmac.digest('base64');
}

function gsonStringify(obj) {
    // Mimic Gson serialization (HTML escaping)
    return JSON.stringify(obj)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/=/g, '\\u003d')
        .replace(/&/g, '\\u0026')
        .replace(/'/g, '\\u0027');
}

// --- Generator ---
function createRealisticPayload() {
    // 1. AES Session Key: 32 Random Bytes
    const sessionKeyBytes = crypto.randomBytes(32);
    
    // 2. Encrypt Session Key (RSA) - "Double Base64" quirk confirmed
    const realXml = getRealXmlFromB64(SERVER_PUB_KEY_B64);
    // const pubKeyPem = xmlToPem(realXml); // Removed
    const sessionDES = encryptSessionKeyRSA(sessionKeyBytes, realXml);

    // 3. Prepare Plaintext Body
    const baseBody = {
        "devSeq": 90,
        "clientDeviceID": "a2a04ece-db28-353c-900f-5bc7cb8f56ed",
        "appName": "MOBILE",
        "devicePubKey": CLIENT_PUB_KEY_B64,
        "deviceName": "Pixel 6a",
        "version": "3.2.9",
        "language": "vi-vn",
        "passWord": "ftrfrcv", // Updated from trace
        "uniqueNo": "",
        "username": "09575252", // Updated from trace
        "gcmId": "d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg",
        "userID": "09575252", // Updated from trace
        "sessionDES": sessionDES,
        "sms_otp": "",
        "bioPassword": "",
        "login_type": "flexi_app",
        "isRoot": "false",
        "Channel": "MOBILE",
        "encrypt": false,
        "osType": "AND"
    };

    const finalPlainBodyStr = gsonStringify(baseBody);
    
    // 4. Calculate hashReqBody
    // Logic: HMAC-SHA256( Key = AES Session Key Bytes, Data = Plaintext Gson-Escaped Body String )
    const hashReqBody = crypto.createHmac('sha256', sessionKeyBytes)
        .update(finalPlainBodyStr)
        .digest('base64');

    // 5. Encrypt Body (AES)
    // Logic: AES-256-CBC( Key = AES Session Key Bytes, Data = Plaintext Gson-Escaped Body String )
    // Note: encryptBodyAES handles IV generation and prepending.
    const reqBodyBase64 = encryptBodyAES(finalPlainBodyStr, sessionKeyBytes);

    // 6. Prepare Header
    const requestHeader = {
        "osType": "AND",
        "TranSeq": Math.floor(Math.random() * 90000000 + 10000000).toString(),
        "trandate": new Date().toLocaleString('en-GB').replace(',', ''), // "25/12/2025 10:33:43"
        "encrypt": false,
        "ErrorCode": 0,
        "appName": "PGBankMobile",
        "gcmId": baseBody.gcmId,
        "devSeq": "1", // This seems fixed at 1 in header, but 90 in body? Check log.
        "version": "3.2.9",
        "language": "vi-vn",
        "hashReqBody": hashReqBody, // Validated: Must be present in Header
        "isRoot": "false",
        "IpAddress": "103.63.114.42",
        "UniqueDeviceId": baseBody.clientDeviceID,
        "isNfcAvailable": "Y"
    };
    const requestHeaderStr = JSON.stringify(requestHeader);

    return {
        "requestHeader": requestHeaderStr,
        "hashReqBody": hashReqBody,
        "language": "vi-vn",
        "ReqBody": reqBodyBase64, // Note Capital 'R' in ReqBody based on some logs, check consistency
        "osType": "AND",
        "devicePubKey": CLIENT_PUB_KEY_B64,
        "sessionDES": sessionDES
    };
}

const payload = createRealisticPayload();
console.log(JSON.stringify(payload, null, 2));
