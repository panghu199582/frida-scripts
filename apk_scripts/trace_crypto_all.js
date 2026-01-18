
Java.perform(function() {
    console.log("[*] 🛡️ 启动全加密算法监控 (Java + Native)...");
    
    // ==========================================================
    // 1. Java Cryptography Architecture (JCA) Monitor
    // 1. Java Cryptography Architecture (JCA) Monitor
    // ==========================================================
    // var ByteString = Java.use("okio.ByteString"); // REMOVED: Caused ClassNotFoundException

    // Helper: Hexdump (Pure JS implementation)
    function toHex(b) {
        if (!b) return "null";
        var s = "";
        // Convert signed byte to unsigned and then hex
        for(var i=0; i<Math.min(b.length, 128); i++) { // Limit length to avoid massive logs
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        if(b.length>128) s+="... ("+b.length+" bytes)";
        return s;
    }

    // A. Hook MAC (HMAC-SHA1, HMAC-SHA256, etc.) -> 最可能是 OCRA
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload('[B').implementation = function(input) {
            var algo = this.getAlgorithm();
            var ret = this.doFinal(input);
            console.log("\n[J] 🗝️ Mac.doFinal (" + algo + ")");
            console.log("    Input : " + toHex(input));
            console.log("    Output: " + toHex(ret));
            // Check if output could be truncated to OTP (usually first 4 bytes used)
            return ret;
        }
        // doFinal() void arg
        Mac.doFinal.overload().implementation = function() {
            var algo = this.getAlgorithm();
            var ret = this.doFinal();
            console.log("\n[J] 🗝️ Mac.doFinal (" + algo + ") [Buffered]");
            console.log("    Output: " + toHex(ret));
            return ret;
        }
    } catch(e) {}

    // B. Hook MessageDigest (SHA-1, SHA-256) -> OCRA 基础
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var algo = this.getAlgorithm();
            var ret = this.digest(input);
            console.log("\n[J] 🥣 MessageDigest.digest (" + algo + ")");
            console.log("    Input : " + toHex(input)); // ⚠️ 看看这里是不是你的 4位 Code
            console.log("    Output: " + toHex(ret));
            return ret;
        }
    } catch(e) {}

    // C. Hook Cipher (AES, RSA) -> 可能用于加密 PIN
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            // 过滤太长的，只看短的
            if (input && input.length < 256) {
                console.log("\n[J] 🔐 Cipher.doFinal (" + this.getAlgorithm() + ")");
                console.log("    Input : " + toHex(input));
                console.log("    Output: " + toHex(ret));
            }
            return ret;
        }
    } catch(e) {}
    
    
    // ==========================================================
    // 2. Native Search (Looking for custom crypto libs)
    // ==========================================================
    // 如果它没有用系统 libcrypto，而是静态编译，我们遍历所有 .so 的导出表看有没有类似 HMAC 的函数
    /*
    var modules = Process.enumerateModules();
    var suspectFunctions = [];
    modules.forEach(function(m) {
        if (m.path.indexOf(".so") !== -1 && m.path.indexOf("/system/") === -1) {
            // Only examine App libs
            var exports = m.enumerateExports();
            exports.forEach(function(e) {
                if (e.name.toLowerCase().indexOf("hmac") !== -1 || e.name.toLowerCase().indexOf("sha1") !== -1) {
                    console.log("[N] Found Suspect Native Export: " + e.name + " @ " + m.name);
                    try {
                        Interceptor.attach(e.address, {
                            onEnter: function(args) {
                                console.log("\n[N] 🧨 Tapped Native: " + e.name + " (" + m.name + ")");
                                // Guessing args: Data usually in first few args
                                // console.log(hexdump(args[0], {length:16}));
                            }
                        });
                    } catch(err) {}
                }
            });
        }
    });
    */
    
    console.log("[*] Java Crypto Hooks Active. Trigger OTP now...");
});
