
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动文件解密监控...");
    
    // The first few bytes of the encrypted file (from our analysis)
    // 2b 62 44 25
    var FILE_HEADER = "2b624425";

    function toHex(b) {
        if (!b) return "";
        var s = "";
        for(var i=0; i<Math.min(b.length, 32); i++) {
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        return s;
    }

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            
            // Check if input matches our file (De-cryption)
            var inputHex = toHex(input);
            if (inputHex.indexOf(FILE_HEADER) === 0) {
                console.log("\n================ [FOUND DECRYPTION] ================");
                console.log("📂 正在解密目标文件 (MY_ALL_EXTERNAL_BANKS)!");
                console.log("📥 Input Prefix : " + inputHex);
                console.log("⚙️  Cipher Algo : " + this.getAlgorithm());
                
                // Print the result (Decrypted text - likely JSON)
                var retStr = "";
                for(var i=0; i<Math.min(ret.length, 200); i++) retStr += String.fromCharCode(ret[i]);
                console.log("🔓 Decrypted (First 200 chars): " + retStr);
                console.log("==================================================\n");
            }
            
            return ret;
        }

        // Also Hook init to catch the key
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, spec) {
            // opmode 2 is DECRYPT_MODE
            if (opmode === 2) {
                 // Store current key for later reference in doFinal if needed (simplified here)
                 // We just print all decrypt inits, hoping to see the one just before our file
                 // To avoid noise, we can't filter easily until we match the data. 
                 // But we can print the Key if we suspect this is THE one.
            }
            return this.init(opmode, key, spec);
        }

    } catch(e) {
        console.log("[-] Error hooking Cipher: " + e);
    }
    
    console.log("[*] 请完全退出 App，然后重新打开，并进入转账界面，以触发文件读取...");
});
