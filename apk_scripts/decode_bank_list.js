
const fs = require('fs');

const inputFile = './MY_ALL_EXTERNAL_BANKS_base64.txt';
const outputFile = './MY_ALL_EXTERNAL_BANKS.bin';

try {
    const b64Data = fs.readFileSync(inputFile, 'utf8').trim();
    const buf = Buffer.from(b64Data, 'base64');
    fs.writeFileSync(outputFile, buf);
    
    console.log("Decoded size: " + buf.length);
    console.log("First 32 bytes (Hex):");
    console.log(buf.slice(0, 32).toString('hex'));
    
    // Check for GZIP magic number 1f 8b
    if (buf[0] === 0x1f && buf[1] === 0x8b) {
        console.log("-> Format: GZIP Detected!");
    } else {
        console.log("-> Format: Unknown (Likely Encrypted)");
    }
    
} catch(e) {
    console.error("Error: " + e.message);
}
