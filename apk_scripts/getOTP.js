const crypto = require('crypto');

function calculatePvcomOtp(suite, keyHex, challengeDec) {
    // 1. Prepare SuiteString bytes
    const suiteBytes = Buffer.from(suite, 'utf8');

    // 2. Process QN08 Challenge
    // Convert decimal challenge to Hex uppercase
    let challengeHex = BigInt(challengeDec).toString(16).toUpperCase();
    
    // Pad to 256 characters (128 bytes) with trailing zeros
    // (Right-padding as per the Python script logic: challenge_hex += "0")
    while (challengeHex.length < 256) {
        challengeHex += "0";
    }

    const challengeBytes = Buffer.from(challengeHex, 'hex');

    // 3. Concatenate Final Data: [Suite] + [0x00] + [ChallengeBytes]
    const finalData = Buffer.concat([
        suiteBytes,
        Buffer.from([0x00]),
        challengeBytes
    ]);

    // 4. Calculate HMAC-SHA1
    const keyBytes = Buffer.from(keyHex, 'hex');
    const hmac = crypto.createHmac('sha1', keyBytes);
    hmac.update(finalData);
    const h = hmac.digest();

    // 5. Dynamic Truncation
    // offset = h[-1] & 0x0f
    const offset = h[h.length - 1] & 0x0f;

    // Extract 4 bytes starting at offset
    const binary = (
        ((h[offset] & 0x7f) << 24) |
        ((h[offset + 1] & 0xff) << 16) |
        ((h[offset + 2] & 0xff) << 8) |
        (h[offset + 3] & 0xff)
    );

    // 6. Modulo 1000000 to get 6-digit OTP
    const otp = binary % 1000000;
    
    // Return as string padded with zeros
    return otp.toString().padStart(6, '0');
}

// --- Verify Data ---
const suite = "OCRA-1:HOTP-SHA1-6:QN08";
const key = "4E6F6978795A3831373636333134333334373232";
const challenge = "23221672";

console.log("Suite:", suite);
console.log("Key:", key);
console.log("Challenge:", challenge);

const result = calculatePvcomOtp(suite, key, challenge);
console.log(`Calculated OTP: ${result}`);
// Expected: 755841
