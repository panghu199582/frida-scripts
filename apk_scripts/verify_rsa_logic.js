const crypto = require('crypto');
const forge = require('node-forge');

// 1. Inputs from the Log
// The AES Key used for encryption (from AES/CBC log)
const aesKeyBase64_Original = "yjEBnBr+JqIGT+FvXU773mJXkpIvdkY/joqtw0/YI+0=";

// The Input captured at the RSA Encryption step
const rsaInputBase64_Captured = "eWpFQm5CcitKcUlHVCtGdlhVNzczbUpYa3BJdmRrWS9qb3F0dzAvWUkrMD0=";

// 2. Verification
console.log("--- Verifying sessionDES Generation Logic ---");
console.log("1. AES Key (from Cipher Init):", aesKeyBase64_Original);
console.log("2. RSA Input (Captured B64):  ", rsaInputBase64_Captured);

// Decode the Captured RSA Input to see what it really is
const rsaInputDecoded = Buffer.from(rsaInputBase64_Captured, 'base64').toString('utf8');
console.log("3. RSA Input (Decoded UTF8):  ", rsaInputDecoded);

// Check if they match
if (rsaInputDecoded === aesKeyBase64_Original) {
    console.log("\n✅ CONFIRMED: The input to RSA Encryption is simply the Base64 String of the AES Key.");
    console.log("   Logic: RSA_Encrypt( Base64( AES_Key_Bytes ) )");
} else {
    console.log("\n❌ MISMATCH: The RSA input does not match the AES Key string.");
}
