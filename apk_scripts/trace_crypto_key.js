
Java.perform(function() {
    console.log("[*] 🔐 启动密钥捕获脚本 (Enhanced)...");

    function toHex(b) {
        if (!b) return "null";
        var s = "";
        for(var i=0; i<Math.min(b.length, 128); i++) {
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        return s;
    }

    function toBase64(b) {
        if (!b) return "null";
        try {
            var Base64 = Java.use("android.util.Base64");
            return Base64.encodeToString(b, 2); // NO_WRAP = 2
        } catch(e) {
            return "[Base64 Error: " + e + "]";
        }
    }

    try {
        var Mac = Java.use("javax.crypto.Mac");
        
        // --- Hook init(Key) ---
        var initHook = Mac.init.overload('java.security.Key');
        initHook.implementation = function(key) {
            console.log("\n[+] 🗝️ Mac.init(Key) called!");
            try {
                var algo = this.getAlgorithm();
                console.log("    Algorithm : " + algo);
                
                var encoded = key.getEncoded();
                if (encoded) {
                    console.log("    🔥 SECRET KEY (Hex) : " + toHex(encoded));
                    console.log("    🔥 SECRET KEY (B64) : " + toBase64(encoded));
                    
                    // Also print string representation if it looks like ASCII
                    var str = "";
                    for(var i=0; i<encoded.length; i++) {
                         var c = encoded[i];
                         if (c >= 32 && c <= 126) {
                             str += String.fromCharCode(c);
                         } else {
                             str += ".";
                         }
                    }
                    console.log("    🔥 SECRET KEY (Str) : " + str);

                } else {
                    console.log("    Key.getEncoded() returned null. Key class: " + key.$className);
                }
            } catch(e) {
                console.log("    Error inspecting key: " + e);
            }
            return this.init(key);
        }

        // --- Hook init(Key, AlgorithmParameterSpec) ---
        try {
            var initSpecHook = Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
            initSpecHook.implementation = function(key, spec) {
                console.log("\n[+] 🗝️ Mac.init(Key, Spec) called!");
                try {
                    var encoded = key.getEncoded();
                    if (encoded) console.log("    🔥 SECRET KEY : " + toHex(encoded));
                } catch(e) {}
                return this.init(key, spec);
            }
        } catch(e) {
            console.log("[-] init(Key, Spec) overload not found or failed hook");
        }

        // --- Hook doFinal(byte[]) ---
        var doFinalHook = Mac.doFinal.overload('[B');
        doFinalHook.implementation = function(input) {
            var algo = this.getAlgorithm();
            // Optional: Filter only interesting algos like HmacSHA1
            
            // Execute original first
            var ret = this.doFinal(input);
            
            // Log Input (Time Step)
            if (input && input.length <= 16) { // Usually 8 bytes for TOTP
                console.log("\n[J] Mac.doFinal (" + algo + ")");
                console.log("    Input (Hex) : " + toHex(input));
                // console.log("    Output (Hex): " + toHex(ret));
            }
            return ret;
        }

        console.log("[+] Hooking complete. Waiting for crypto operations...");

    } catch(e) {
        console.log("[-] FATAL Error hooking javax.crypto.Mac: " + e);
        if (e.message && e.message.indexOf("okio") !== -1) {
            console.log("    (It seems okio library is missing, but this script no longer depends on it.)");
        }
    }
});
