
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动解密监控 V5 (构造函数捕获版)...");
    var TARGET_STR = "PHUONG DONG";

    function toHex(b) {
        if (!b) return "null";
        var s = "";
        for(var i=0; i<b.length; i++) {
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        return s;
    }

    // 1. Hook SecretKeySpec 构造 (捕捉密钥生成)
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
            if (algo === "AES") {
                var kHex = toHex(key);
                console.log("\n[+] 🗝️ 创建 AES 密钥!");
                console.log("    Key Hex: " + kHex);
                // Try Ascii
                var ascii = "";
                for(var i=0; i<key.length; i++) {
                    var c = key[i];
                    if (c >= 32 && c <= 126) ascii += String.fromCharCode(c);
                    else ascii += ".";
                }
                console.log("    Key Str: " + ascii);
            }
            return this.$init(key, algo);
        }
    } catch(e) {}

    // 2. Hook IvParameterSpec 构造 (捕捉 IV 生成)
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload('[B').implementation = function(iv) {
            console.log("\n[+] 🎲 创建 IV!");
            console.log("    IV Hex : " + toHex(iv));
            return this.$init(iv);
        }
    } catch(e) {}

    // 3. Hook Cipher.doFinal (只负责看结果)
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            if (ret) {
                try {
                    var s = "";
                    for(var i=0; i<Math.min(ret.length, 100); i++) s += String.fromCharCode(ret[i]);
                    
                    var interesting = false;
                    if (s.indexOf(TARGET_STR) !== -1) interesting = true;
                    if (ret.length > 500 && (s.trim().startsWith("{") || s.trim().startsWith("["))) interesting = true;
                    
                    if (interesting) {
                        console.log("\n[+] 🔓 Cipher.doFinal 解密成功!");
                        console.log("    Size: " + ret.length);
                        console.log("    Preview: " + s.substring(0, 80).replace(/\n/g, " "));
                        console.log("    (请向上翻阅日志查找最近创建的 AES Key 和 IV)");
                    }
                } catch(e) {}
            }
            return ret;
        }
    } catch(e) {}

    console.log("[*] V5 脚本就绪。Key 和 IV 将在创建时直接打印。");
});
