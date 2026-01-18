
const crypto = require('crypto');

// === 您的已知数据 ===
const HASH_B64 = "Owum+g4jx0QxVLXQs2syPKjf6Dg=";
const EXPECTED_OTP = 635152;
// ===================

function solve() {
    const hash = Buffer.from(HASH_B64, 'base64');
    console.log("Raw Hash Hex:", hash.toString('hex'));

    // 尝试所有可能的 Offset (0 到 16)
    for (let offset = 0; offset <= hash.length - 4; offset++) {
        // 1. Big Endian
        let valBE = hash.readUInt32BE(offset);
        // Mask standard (remove sign bit)
        let maskedBE = valBE & 0x7fffffff;
        
        if (check(maskedBE, offset, "Big Endian")) return;
        if (check(valBE, offset, "Big Endian (No Mask)")) return;

        // 2. Little Endian
        let valLE = hash.readUInt32LE(offset);
        let maskedLE = valLE & 0x7fffffff;
        
        if (check(maskedLE, offset, "Little Endian")) return;
        if (check(valLE, offset, "Little Endian (No Mask)")) return;
    }
    
    console.log("[-] No standard logic found. Trying non-standard...");
}

function check(val, offset, type) {
    let mod = val % 1000000;
    if (mod === EXPECTED_OTP) {
        console.log(`\n[!] 🎉 FOUND MATCH!`);
        console.log(`    Offset: ${offset}`);
        console.log(`    Type  : ${type}`);
        console.log(`    Logic : (readUInt32 at offset ${offset}) % 1000000`);
        return true;
    }
    return false;
}

solve();
