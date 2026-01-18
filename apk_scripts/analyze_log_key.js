const fs = require('fs');
const forge = require('node-forge');

const logContent = fs.readFileSync('/Users/a996/projects/apk/pgbtxt', 'utf8');

// Find devicePubKey in reqBody (Line 27 approx)
const match = logContent.match(/"devicePubKey":"(PFJT.*?)"/);
if (match) {
    const key = match[1];
    console.log("Found devicePubKey length:", key.length);
    
    // Check key size
    try {
        const xml = Buffer.from(key, 'base64').toString('utf8');
        const modulusMatch = xml.match(/<Modulus>(.*?)<\/Modulus>/);
        if (modulusMatch) {
            const modB64 = modulusMatch[1];
            const modBytes = Buffer.from(modB64, 'base64');
            console.log("Modulus Bytes:", modBytes.length);
            console.log("Modulus Bits:", modBytes.length * 8);
        }
    } catch(e) { console.log(e); }
} else {
    console.log("devicePubKey not found in pgbtxt");
}
