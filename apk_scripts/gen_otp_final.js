
const crypto = require('crypto');

function generateTOTP() {
    // === CONFIGURATION ===
    // 🔔 FROM LOGS (Step 37):
    // 🔥 SECRET KEY (Str) : DEV0000747154TQ5WUEU7255085727410218189
    
    const FINAL_KEY = "DEV0000747154TQ5WUEU7255085727410218189";

    // 自动转换为 Hex
    const SECRET_KEY_HEX = Buffer.from(FINAL_KEY, 'utf8').toString('hex');

    // 1. Time Step (30s window)
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = Math.floor(epoch / 30);
    
    // Log Verification:
    // Input (Hex) : 000000000382ff6d  => 58916717
    // This matches the current time range roughly.

    // 2. Buffer (8 bytes)
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(timeStep / 0x100000000), 0);
    buf.writeUInt32BE(timeStep & 0xffffffff, 4);

    // 3. HMAC-SHA1 (Confirmed Algorithm for OTP)
    // Note: The logs also show HmacSHA256, but that is likely for API signing, not OTP.
    const hmac = crypto.createHmac('sha1', Buffer.from(SECRET_KEY_HEX, 'hex'));
    hmac.update(buf);
    const digest = hmac.digest();

    // 4. Dynamic Offset
    const offset = digest[digest.length - 1] & 0xf;

    // 5. Truncate
    const binary = digest.readUInt32BE(offset) & 0x7fffffff;
    const otp = (binary % 1000000).toString().padStart(6, '0');

    console.log(`\n============== TOTP GENERATOR ==============`);
    console.log(`🔑 Key (Str) : ${FINAL_KEY}`);
    console.log(`⏳ Step      : ${timeStep}`);
    console.log(`🎁 OTP       : ${otp}`);
    console.log(`============================================\n`);
}

setInterval(() => {
    generateTOTP();
}, 1000)

