
const fs = require('fs');
const crypto = require('crypto');

const inputFile = './MY_ALL_EXTERNAL_BANKS.bin';
const outputFile = './MY_ALL_EXTERNAL_BANKS_decrypted.json';

// From Step 159 Logs
const KEY_HEX = "3559795356364277316a504b53344e755346644d7a7a577755535a5853624431";
const IV_HEX  = "7f1b041c7586c6ba094c913725eeb039";

try {
    const fullData = fs.readFileSync(inputFile);
    
    // 1. The Strongest Key Candidate (ASCII: 5YySV6Bw1jPKS4NuSFdMzzWwUSZXSbD1)
    const KEY_HEX = "3559795356364277316a504b53344e755346644d7a7a577755535a5853624431";
    // 2. The Captured IV
    const CAPTURED_IV_HEX = "7f1b041c7586c6ba094c913725eeb039";

    const key = Buffer.from(KEY_HEX, 'hex');
    const capturedIv = Buffer.from(CAPTURED_IV_HEX, 'hex');
    const zeroIv = Buffer.alloc(16, 0);

    console.log(`Testing Key: ${key.toString('utf8')}`);

    function tryDecrypt(desc, algo, k, i, data) {
        try {
            const decipher = crypto.createDecipheriv(algo, k, i);
            decipher.setAutoPadding(false); // Disable padding to see result even if wrong
            
            let decrypted = decipher.update(data);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            // Check content
            const s = decrypted.toString('utf8');
            // Look for "PHUONG DONG" or JSON
            if (s.indexOf("PHUONG DONG") !== -1 || s.indexOf("bankId") !== -1 || (s.indexOf("{") !== -1 && s.indexOf("}") !== -1)) {
                console.log(`\n[SUCCESS] Strategy: ${desc}`);
                console.log(`Preview: ${s.substring(0, 100).replace(/\n/g, ' ')}...`);
                fs.writeFileSync(outputFile, decrypted);
                console.log("Saved!");
                process.exit(0);
            }
        } catch(e) { /* ignore */ }
    }

    // 1. Standard CBC with Captured IV
    tryDecrypt("CBC + Captured IV", 'aes-256-cbc', key, capturedIv, fullData);

    // 2. CBC with IV at start of file (First 16 bytes = IV)
    if (fullData.length > 16) {
        const fileIv = fullData.slice(0, 16);
        const fileData = fullData.slice(16);
        tryDecrypt("CBC + File Prefix IV", 'aes-256-cbc', key, fileIv, fileData);
    }
    
    // 3. CBC with Zero IV
    tryDecrypt("CBC + Zero IV", 'aes-256-cbc', key, zeroIv, fullData);

    // 4. ECB (Ignores IV)
    try {
        const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
        decipher.setAutoPadding(false);
        let d = decipher.update(fullData);
        d = Buffer.concat([d, decipher.final()]);
        if (d.toString().indexOf("PHUONG DONG") !== -1 || d.indexOf("{") !== -1) {
             console.log(`\n[SUCCESS] Strategy: AES-256-ECB`);
             fs.writeFileSync(outputFile, d);
             process.exit(0);
        }
    } catch(e) {}

    console.log("[-] All brute force strategies failed.");

} catch(e) {
    console.error("Error: " + e.message);
}
