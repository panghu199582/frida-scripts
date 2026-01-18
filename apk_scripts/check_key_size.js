const forge = require('node-forge');

const DEVICE_PUB_KEY_B64 = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjh5blFCVlJjK0JRZXFnakNUMk56OVQ2Zy8xcGJTemJSREExbjEwZVZFalRqYnE1NjZmQkNBSG1WK0R3Ung2bUpFMWJhT2REeDFuVURaWEQ5RGtoNXF2UHlWYkcrN1hsNUtGS3prVEN5OXpmbmxTSnFjTGI2MjhocnhmdUsybFprZDdQcnhjbUZpTmw4cUJaZGFuR0hFeVQ2TWNObkdlS29FQlFMZnV3MmM4RUc0Zm9WYU1VTmc2enQrVmh6eFRrTG9OYjUxWFNDTVM2d3psVHhDSnNiRVBiMEdxQnZzbXhpVTZBVnJZTldkZnU4SzhaellIWlVRKy95NkJPZkxxRk1rSmd5elJpUFNFTG5WYjdZNmQ1d0cxbktlZjl2QVNNUFBHNmFJNE0vSW95bTJNazVITmdZREZZSlNyeFFYOGJRKytzRVJWQ25tSGRaemFXTkJqYUVhdz09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==";

function getRealXmlFromB64(b64) {
    return Buffer.from(b64, 'base64').toString('utf8');
}

const xml = getRealXmlFromB64(DEVICE_PUB_KEY_B64);
console.log("XML:", xml);

const modulusMatch = xml.match(/<Modulus>(.*?)<\/Modulus>/);
if (modulusMatch) {
    const modulusB64 = modulusMatch[1];
    const modulusBytes = Buffer.from(modulusB64, 'base64');
    console.log("Modulus Byte Length:", modulusBytes.length);
    console.log("Modulus Bit Length:", modulusBytes.length * 8);
}
