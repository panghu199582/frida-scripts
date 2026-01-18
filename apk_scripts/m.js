const crypto = require('crypto');

/**
 * 完美还原 App 的 AES-256 加密逻辑
 * @param {string} pin - 用户 PIN (如 "787878")
 * @param {string} envHash - 环境检测 Hash (那个很长的字符串)
 * @param {string} timestamp - 13位时间戳字符串
 * @returns {string} Base64 格式的密文
 */
function encryptPin(pin, envHash, timestamp) {
    // 1. 准备 Key: 直接取 Hash 字符串的前 32 个字符作为密钥
    // 注意：这里不是 Hex 解码，而是直接拿字符的 ASCII 码
    const keyString = envHash.substring(0, 32);
    const key = Buffer.from(keyString, 'utf8');

    // 2. 准备 IV: 时间戳字符串，右侧补 0x00 直到 16 字节
    const ivBuffer = Buffer.alloc(16);
    ivBuffer.write(timestamp, 0, 'utf8'); 
    // Buffer.alloc 默认填0，所以 write 进去后后面自动就是 0 了，无需手动补

    // 3. 生成 4 位随机盐 (1000 - 9999)
    const randomSalt = Math.floor(Math.random() * 9000) + 1000;

    // const randomSalt = 8157;

    // 4. 拼接明文: 随机盐 + PIN + 时间戳
    const plainText = randomSalt.toString() + pin + timestamp;

    console.log(`[Debug] 生成明文: ${plainText}`);
    console.log(`[Debug] 使用密钥: ${keyString}`);

    // 5. AES-256-CBC 加密
    try {
        const cipher = crypto.createCipheriv('aes-256-cbc', key, ivBuffer);
        let encrypted = cipher.update(plainText, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return encrypted;
    } catch (e) {
        console.error("加密错误:", e);
        return null;
    }
}

// --- 使用示例 ---

// 这里的 Hash 即使给全了，代码里也只会截取前 32 位，符合 App 逻辑
const FULL_HASH = "571e0c95ab4bf617e61527a838fa5c9919d2af8ce3a8f4fe04585f";
const PIN = "787878";
const TS = "1767962001758";

const result = encryptPin(PIN, FULL_HASH, TS);
console.log("\n生成的最终密文:");
console.log(result);