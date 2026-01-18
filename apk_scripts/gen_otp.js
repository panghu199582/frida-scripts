
const crypto = require('crypto');

// === NEW KEY from Arg0 ===
// Decimal: 68,69,86,48,48,48,48,55,51,55,51,57,48,76,51,68,90,55,51,76,48,55,48,55,50,50,48,52,54,49,57,52,48,55,50,57,55,50,50
// String : DEV0000737390L3DZ73L0707220461940729722 (Sample)
// Hex    : 444556303030303733373339304c33445a37334c30373037323230343631393430373239373232
const SECRET_KEY_HEX = "444556303030303733373339304c33445a37334c30373037323230343631393430373239373232";
const ALGO = 'sha256'; 
const DIGITS = 6;
const PERIOD = 30;

function generateTOTP() {
    // 1. Calculate Time Step
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = Math.floor(epoch / PERIOD);

    // 2. Convert to 8-byte Buffer (Big Endian)
    const buf = Buffer.alloc(8);
    const high = Math.floor(timeStep / 0x100000000);
    const low = timeStep & 0xffffffff;
    buf.writeUInt32BE(high, 0);
    buf.writeUInt32BE(low, 4);

    // 3. HMAC-SHA256
    const keyBuf = Buffer.from(SECRET_KEY_HEX, 'hex');
    const hmac = crypto.createHmac(ALGO, keyBuf);
    hmac.update(buf); // Data is the Time Step
    const digest = hmac.digest();

    // 4. Standard Truncate
    const offset = digest[digest.length - 1] & 0xf;
    const binary =
        ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, DIGITS);

    // 5. Pad
    let otpStr = otp.toString();
    while (otpStr.length < DIGITS) otpStr = "0" + otpStr;

    console.log(`\n============== TOTP VERIFIER ==============`);
    console.log(`🔑 Key (Hex): ${SECRET_KEY_HEX.substring(0, 10)}...`);
    console.log(`⏳ Step     : ${timeStep} (App used 58897495)`);
    console.log(`🎁 OTP      : ${otpStr}`);
    console.log(`===========================================\n`);
}

generateTOTP();
