// Dump HMAC Data to Reverse-Engineer the Secret
// Usage: frida -U -f com.telkom.mwallet -l dump_hmac_data.js

Java.perform(function() {
    console.log("[*] 🕵️ Searching for HMAC in libssl/libcrypto...");
    
    // Common OpenSSL HMAC symbols
    var hmacSyms = [
        "HMAC",
        "HMAC_Update", 
        "HMAC_Final",
        "EVP_DigestSignUpdate"
    ];

    var targetFunc = null;

    // Try finding in libcrypto or libssl
    Process.enumerateModules().forEach(function(m) {
        if (m.name.indexOf("crypto") !== -1 || m.name.indexOf("ssl") !== -1) {
             m.enumerateExports().forEach(function(e) {
                 if (e.name == "HMAC") {
                     console.log("   Found Global HMAC in " + m.name);
                     targetFunc = e.address;
                 }
             });
        }
    });

    if (targetFunc) {
        console.log("[*] Hooking HMAC at " + targetFunc);
        
        Interceptor.attach(targetFunc, {
            onEnter: function(args) {
                // HMAC(evp, key, key_len, data, data_len, ...)
                // args[0] = EVP Type
                // args[1] = Key Ptr  <-- CHECK THIS
                // args[2] = Key Len
                // args[3] = Data Ptr <-- THIS IS WHAT WE WANT
                // args[4] = Data Len
                
                try {
                    var keyLen = args[2].toInt32();
                    var dataLen = args[4].toInt32();
                    
                    if (keyLen > 0 && keyLen < 256) {
                        var keyData = Memory.readByteArray(args[1], keyLen);
                        var keyStr = uint8ToHex(keyData); // Check if Salted (ASCII)
                        var keyAscii = Memory.readUtf8String(args[1], keyLen);
                        
                        // Check if Key matches our SaltedTS pattern (ends with "tw4ll3tn30")
                        if (keyAscii && keyAscii.indexOf("tw4ll3tn30") !== -1) {
                            console.log("\n🔥🔥🔥 FOUND HASH CALL! 🔥🔥🔥");
                            console.log("🔑 Key (SaltedTS): " + keyAscii);
                            
                            // Capture the DATA
                            var dataData = Memory.readByteArray(args[3], dataLen);
                            var dataHex = uint8ToHex(dataData);
                            var dataAscii = Memory.readUtf8String(args[3], dataLen);
                            
                            console.log("📦 Data (Hex): " + dataHex);
                            console.log("📦 Data (Str): " + dataAscii);
                            console.log("---------------------------------------------------");
                            console.log("👉 THIS 'Data' IS THE Hex-Encoded-Shifted String!");
                            console.log("👉 Now use Python to Unshift this and find the Mystery Byte.");
                        }
                    }
                } catch(e) {}
            }
        });
    } else {
        console.log("[-] Could not find 'HMAC' export. Trying 'HMAC_Update'...");
         // Fallback logic could go here
    }
    
    function uint8ToHex(buffer) {
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    }
});
