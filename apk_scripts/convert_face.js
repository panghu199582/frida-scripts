const fs = require('fs');

try {
    // 1. Read the face.txt file
    const fileContent = fs.readFileSync('/Users/a996/projects/apk/face.txt', 'utf8');

    // 2. Extract the Hex string
    // The format seems to be:
    // [BBL_DEBUG]   content-type: application/octet-stream
    // [BBL_DEBUG] [Request Body] (.txt Binary) Hex:
    // <HEX_STRING>
    
    const lines = fileContent.split('\n');
    let hexString = '';
    
    // Find the line that looks like a long hex string (or starts after the label)
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        // Simple heuristic: long line with only hex characters
        if (line.length > 100 && /^[0-9a-fA-F]+$/.test(line)) {
            hexString = line;
            break;
        }
    }

    if (!hexString) {
        console.error("Could not find the Hex string in face.txt");
        process.exit(1);
    }

    console.log(`Found Hex string (length: ${hexString.length})`);

    // 3. Convert Hex to Buffer
    const buffer = Buffer.from(hexString, 'hex');

    // 4. Convert Buffer to Base64 String
    // Note: The hex data *is* the bytes of a Base64 string.
    // So we just need to read the buffer as UTF-8.
    const base64String = buffer.toString('utf8');

    console.log("Converted to Base64 string.");
    console.log("Preview:", base64String.substring(0, 50) + "...");

    // 5. Save the Base64 string to a file
    fs.writeFileSync('/Users/a996/projects/apk/face_base64.txt', base64String);
    console.log("Saved Base64 string to face_base64.txt");

    // 6. (Optional) Decode the Base64 string to the original image to verify
    const imageBuffer = Buffer.from(base64String, 'base64');
    fs.writeFileSync('/Users/a996/projects/apk/face_restored.jpg', imageBuffer);
    console.log("Decoded Base64 to image and saved to face_restored.jpg");

} catch (e) {
    console.error("Error:", e.message);
}
