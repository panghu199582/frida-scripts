const crypto = require('crypto');
const forge = require('node-forge');

// 1. Data from User Log
const aesKeyBase64 = "xE4aho+XSBXAaM56JoCMsawdGCLiUK2/jEcnjnehHnU=";
const rsaInputBase64 = "eEU0YWhvK1hTQlhBYU01NkpvQ01zYXdkR0NMaVVLMi9qRWNuam5laEhuVT0=";
const sessionDES = "NqzQ3caTSmIxBVgbBM1QLROcN5m4RqnjVni5WmRybwXv/X4EeGX/qt59k66swAcJdC9w6O5IZo5qBzE0z/mhNPnrG0i3xdW7HBzs8jTMmsKpJyfrxcAdRc1tWLmH4JhikKIFYouLO/KmJJjsv5EBP0ULvttZyc3Zn5MBBZZwfQPoiVdpvM/gQVEgJZrCJmG9g8C1AmWH9FvFLqNKmRJPq3Nu0nXu6ynAQb7UTa+KgrQVUVwheTYBK2X0JoOsypf3oZbvMUHTY1CNYKoBBfkrxgVhbLz1/SeidsMOy/wviEovHlawNfavFwzwlE4rpy+u9vSQkoO7+1WcKiCdNu/Azg==";

console.log("--- Analyzing sessionDES Logic from Logs ---");

// 2. Decode RSA Input
const rsaInputDecoded = Buffer.from(rsaInputBase64, 'base64').toString('utf8');
console.log("AES Key in Log:    ", aesKeyBase64);
console.log("RSA Input Decoded: ", rsaInputDecoded);

if (aesKeyBase64 === rsaInputDecoded) {
    console.log("\n✅ RELATIONSHIP VERIFIED: RSA Input is the AES Key Base64 String!");
    console.log("   Logic: sessionDES = RSA_Encrypt( Base64( AES_Key_Bytes ) )");
    console.log("   In final_encrypt_pgb.js this matches encryptSessionKeyRSA logic.");
} else {
    console.log("\n❌ NO MATCH.");
}
