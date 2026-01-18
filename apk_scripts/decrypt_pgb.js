const crypto = require('crypto');

// 1. 填入 Frida 抓到的 32字节 Hex Key
// 这是你刚才抓到的:
const SESSION_KEY_HEX = "5d7494419c78450202e4d1b880df5d1c54062a418fe7a85dcf6f68ebdf33230e";

// 2. 填入要解密的 Base64 数据
// 注意：不要填 "sessionDES" 那个字符串！那是 RSA 加密后的密钥本身。
// 你应该填入服务器返回的加密响应内容 (通常是 HTTP 响应体里的 Base64 字符串)
// 如果你还没有加密的响应体，请在 Frida 日志中找 [HTTP Response] 或类似的加密内容
const ENCRYPTED_DATA_B64 = "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"; 

function decryptTryAll(keyHex, dataBase64) {
    if (dataBase64 === "YOUR_ENCRYPTED_RESPONSE_BASE64_HERE") {
        console.log("[-] 请先填入要解密的 Base64 数据 (ENCRYPTED_DATA_B64)");
        return;
    }

    console.log(`[*] Cracking with Session Key: ${keyHex}`);
    console.log(`[*] Data Length: ${dataBase64.length}`);

    const keyBuffer = Buffer.from(keyHex, 'hex');
    const dataBuffer = Buffer.from(dataBase64, 'base64');

    // 发现 App 使用了 AES/CTR/NoPadding
    try {
        // CTR 模式通常需要 IV (Counter)。在这个 App 里如果没有看到 IV，可能是全 0。
        // 或者 IV 是 Key 的一部分？或者 IV 在密文前 16 字节？
        // 我们先尝试 IV = All Zeros
        const iv = Buffer.alloc(16, 0); 
        const decipher = crypto.createDecipheriv('aes-256-ctr', keyBuffer, iv);
        let dec = decipher.update(dataBuffer, null, 'utf8');
        dec += decipher.final('utf8');
        console.log("\n✅ [SUCCESS?] Decrypted with AES-256-CTR (IV=0):");
        console.log(dec);
        return;
    } catch (e) {
        console.log("[-] AES-256-CTR (IV=0) failed: " + e.message);
    }
    
    // 尝试把密文前16字节当做 IV
    if (dataBuffer.length > 16) {
        try {
            const iv = dataBuffer.slice(0, 16);
            const content = dataBuffer.slice(16);
            const decipher = crypto.createDecipheriv('aes-256-ctr', keyBuffer, iv);
            let dec = decipher.update(content, null, 'utf8');
            dec += decipher.final('utf8');
            console.log("\n✅ [SUCCESS?] Decrypted with AES-256-CTR (IV=Prefix):");
            console.log(dec);
            return;
        } catch(e) {}
    }

    // 备用：AES-256-ECB (虽然 Log 显示是 CTR，但以防万一)
    try {
        const decipher = crypto.createDecipheriv('aes-256-ecb', keyBuffer, null);
        decipher.setAutoPadding(false); // NoPadding
        let dec = decipher.update(dataBuffer, null, 'utf8');
        dec += decipher.final('utf8');
        console.log("\n✅ [SUCCESS?] Decrypted with AES-256-ECB (NoPadding):");
        console.log(dec);
    } catch (e) {}
}

decryptTryAll(SESSION_KEY_HEX, ENCRYPTED_DATA_B64);
