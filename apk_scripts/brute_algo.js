
const crypto = require('crypto');

// === 最新的一组数据 ===
const KEY_HEX = "444556303030303733373339304c33445a37334c30373037323230343631393430373234303336";
const STEP_NUM = 58897563;
const EXPECTED_OTP = "414447";
// ===================

function tryAlgo(algoName) {
    const keyBuf = Buffer.from(KEY_HEX, 'hex');
    
    const buf = Buffer.alloc(8);
    const high = Math.floor(STEP_NUM / 0x100000000);
    const low = STEP_NUM & 0xffffffff;
    buf.writeUInt32BE(high, 0);
    buf.writeUInt32BE(low, 4);

    const hmac = crypto.createHmac(algoName, keyBuf);
    hmac.update(buf);
    const digest = hmac.digest();

    for (let offset = 0; offset <= digest.length - 4; offset++) {
        // Big Endian
        let valBE = digest.readUInt32BE(offset);
        let maskedBE = valBE & 0x7fffffff; // Standard Mask
        let otpBE = (maskedBE % 1000000).toString().padStart(6, '0');
        
        let otpBENoMask = (valBE % 1000000).toString().padStart(6, '0');

        if (otpBE === EXPECTED_OTP) {
            console.log(`[matches] Algo: ${algoName}, Offset: ${offset}, Mode: BE Masked`);
            return;
        }
        if (otpBENoMask === EXPECTED_OTP) {
            console.log(`[matches] Algo: ${algoName}, Offset: ${offset}, Mode: BE Raw`);
            return;
        }
        
        // Little Endian
        let valLE = digest.readUInt32LE(offset);
        let maskedLE = valLE & 0x7fffffff;
        let otpLE = (maskedLE % 1000000).toString().padStart(6, '0');
        
        if (otpLE === EXPECTED_OTP) {
             console.log(`[matches] Algo: ${algoName}, Offset: ${offset}, Mode: LE Masked`);
             return;
        }
    }
}

console.log("Brute forcing with NEW data...");
tryAlgo('sha1');
tryAlgo('sha256');
