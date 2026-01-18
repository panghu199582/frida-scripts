/*
 * Pgbank Analysis - Merged Network & Crypto Monitor
 * Combined Features:
 * 1. Network Request/Response Logging (from pgb copy 2.js)
 * 2. Crypto Tracing (KeyGen, Cipher, HMAC)
 */

Java.perform(function() {
    var StringClass = Java.use("java.lang.String");
    var Base64 = Java.use("android.util.Base64");
    var Charset = Java.use("java.nio.charset.Charset");
    var utf8 = Charset.forName("UTF-8");
    var ProxyClass = Java.use("java.lang.reflect.Proxy");
    var ObjectClass = Java.use("java.lang.Object");

    console.log("[*] Initializing Pgbank Comprehensive Monitor...");

    // ================== UTILS ==================
    function toHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        for(var i=0; i<Math.min(bytes.length, 256); i++) {
            var b = bytes[i] & 0xFF;
            if (b < 16) hex += "0";
            hex += b.toString(16);
        }
        return hex + (bytes.length > 256 ? "..." : "");
    }

    function toBase64(bytes) {
        if (!bytes) return "null";
        return Base64.encodeToString(bytes, 2); // NO_WRAP
    }

    function byteArrayToString(bytes) {
        if (!bytes) return "null";
        try {
            var str = StringClass.$new(bytes, "UTF-8");
            var readable = 0;
            for(var i=0; i<Math.min(str.length(), 100); i++) {
                var c = str.charCodeAt(i);
                if ((c >= 32 && c <= 126) || c == 10 || c == 13) readable++;
            }
            if (readable / Math.min(str.length(), 100) > 0.8) return str.toString();
        } catch(e) {}
        return "[Binary Data]";
    }

    function inspectObject(obj, depth) {
        if (depth === undefined) depth = 0;
        if (depth > 3) return "..."; 
        if (obj === null || obj === undefined) return "null";
        try {
            var javaObj = Java.cast(obj, ObjectClass);
            var cls = javaObj.getClass();
            var clsName = cls.getName();
            return "[" + clsName + "]@" + javaObj.hashCode().toString(16);
        } catch(e) { return "[Inspect Error]"; }
    }

    // ================== NETWORK HOOKS (From pgb copy 2.js) ==================

    // 1. OkHttp Request Monitoring (o.a0 -> Request)
    try {
        var Client = Java.use("o.a0");
        var clientMethods = Client.class.getDeclaredMethods();
        clientMethods.forEach(function(m) {
            var params = m.getParameterTypes();
            if (params.length === 1) {
                 var overloads = Client[m.getName()].overloads;
                 overloads.forEach(function(ov) {
                    ov.implementation = function(req) {
                        var reqInfo = "";
                        try { reqInfo = req.toString(); } catch(e) { reqInfo = "[Req Null]"; }
                        console.log("\n[OkHttp Request] " + m.getName() + "(): " + reqInfo);
                        if (reqInfo.indexOf("Request") === -1 && reqInfo.indexOf("http") === -1) {
                             console.log("  [Request Dump]:\n" + inspectObject(req, 0));
                        }
                        return this[m.getName()](req);
                    }
                });
            }
        });
        console.log("[+] Hooked o.a0 (OkHttp Client)");
    } catch(e) { console.log("[-] o.a0 Hook Error: " + e); }

    // 2. Response Decompression (GZIP/Inflater - Captures Response Body)
    function tryTraceDecompression(name) {
        try {
            var Clazz = Java.use(name);
            var readMethods = Clazz.read.overloads;
            readMethods.forEach(function(method) {
                method.implementation = function() {
                    var ret = method.apply(this, arguments);
                    try {
                        if (ret > 0 && arguments.length >= 1 && arguments[0] != null) {
                            var buffer = arguments[0];
                            var offset = (arguments.length >= 2) ? arguments[1] : 0;
                            var length = ret; 
                            var s = StringClass.$new(buffer, offset, length, utf8).toString();
                            
                            if(s.trim().startsWith("{") || s.trim().startsWith("[")) {
                                console.log("\n⬇️ [BODY-DECODED] (" + name + "):\n" + s);
                            }
                        }
                    } catch(e) {}
                    return ret;
                }
            });
        } catch(e) {}
    }
    tryTraceDecompression("java.util.zip.GZIPInputStream");
    tryTraceDecompression("java.util.zip.InflaterInputStream");
    
    // Low-level Inflater hook
    try {
        var Inflater = Java.use("java.util.zip.Inflater");
        Inflater.inflate.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            var ret = this.inflate(b, off, len);
            if (ret > 0) {
                try {
                    var s = StringClass.$new(b, off, ret, utf8).toString();
                    if(s.trim().startsWith("{") || s.trim().startsWith("[")) {
                         console.log("\n⬇️ [BODY-DECODED] (Inflater):\n" + s);
                    }
                } catch(e) {}
            }
            return ret;
        }
    } catch(e) {}

    // ================== CRYPTO HOOKS (Previously Added) ==================

    // 1. KeyGenerator
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        var SecretKey = Java.use("javax.crypto.SecretKey"); 

        KeyGenerator.generateKey.implementation = function() {
            var key = this.generateKey();
            var algo = this.getAlgorithm();
            console.log("\n🔑 [KeyGenerator] Generated " + algo + " Key");
            try {
                // Key extends java.security.Key which has getEncoded()
                var KeyInterface = Java.use("java.security.Key");
                var castKey = Java.cast(key, KeyInterface);
                var encoded = castKey.getEncoded();
                if (encoded) {
                     console.log("   Key (Hex): " + toHex(encoded));
                     console.log("   Key (Base64): " + toBase64(encoded));
                     if (algo.toUpperCase().includes("AES")) console.log("   👉 POTENTIAL sessionDES (Plaintext) FOUND!");
                }
            } catch(e) { 
                console.log("   [Key Inspect Error]: " + e);
                // Fallback: try raw method call if cast fails
                try {
                    var encoded = key.getEncoded();
                    if (encoded) console.log("   Key (Hex - fallback): " + toHex(encoded));
                } catch(e2) {}
            }
            return key;
        }
    } catch(e) { console.log("KeyGen Hook Error: " + e); }

    // 2. Cipher
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var cipherMap = new Map();

        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
             this.init(mode, key);
             handleInit(this, mode, key, null);
        }
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, spec) {
             this.init(mode, key, spec);
             handleInit(this, mode, key, spec);
        }
        Cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function(mode, key, random) {
             this.init(mode, key, random);
             handleInit(this, mode, key, null);
        }
    
        function handleInit(instance, mode, key, spec) {
            var algo = instance.getAlgorithm();
            var keyEncoded = (key && key.getEncoded()) ? key.getEncoded() : null;
            var keyB64 = keyEncoded ? toBase64(keyEncoded) : "null";
            var ivStr = "null";
            try {
                var iv = instance.getIV();
                if (iv) ivStr = toHex(iv);
            } catch(e) {}
            
            var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : "MODE_" + mode;
            cipherMap.set(instance.hashCode(), { algo: algo, mode: modeStr, keyB64: keyB64, iv: ivStr });

            if (algo.toUpperCase().includes("RSA")) {
                console.log("\n⚙️ [Cipher Init] " + algo + " [" + modeStr + "]");
                console.log("   Provider: " + instance.getProvider().getName());
                
                try {
                    // Try to inspect RSA Key specifically
                    var RSAPublicKey = Java.use("java.security.interfaces.RSAPublicKey");
                    if (key) {
                        var pubKey = Java.cast(key, RSAPublicKey);
                        console.log("   RSA Modulus: " + pubKey.getModulus().toString(16));
                        console.log("   RSA Exponent: " + pubKey.getPublicExponent().toString(16));
                    }
                } catch(e) { } // Ignore if not RSAPublicKey
                
                if (keyB64 !== "null") console.log("   Key (Base64 X.509): " + keyB64);

            } else if (algo.toUpperCase().includes("AES")) {
                console.log("\n⚙️ [Cipher Init] " + algo + " [" + modeStr + "]");
            }
        }

        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            handleDoFinal(this, input, ret);
            return ret;
        }

        function handleDoFinal(instance, input, output) {
            var ctx = cipherMap.get(instance.hashCode());
            if (!ctx) return; 

            var algo = ctx.algo.toUpperCase();
            var mode = ctx.mode;
            
            if (algo.includes("RSA") && mode === "ENCRYPT" && input.length < 256) {
                console.log("\n🔐 [RSA Encryption] Potential sessionDES Encryption!");
                console.log("   Input B64: " + toBase64(input));
                console.log("   Output B64: " + toBase64(output));
            }
            
            if (algo.includes("AES") && mode === "ENCRYPT") {
                var inputStr = byteArrayToString(input);
                console.log("\n📦 [AES Encryption] Potential reqBody Generation!");
                
                // Always print HEX for binary reliability
                console.log("   Input (Hex): " + toHex(input));
                
                // Force Safe View if binary - FULL CONTENT
                var safe = "";
                for(var i=0; i<input.length; i++) {
                    var c = input[i];
                    if ((c >= 32 && c <= 126)) safe += String.fromCharCode(c);
                    else safe += ".";
                }
                console.log("   Input (SafeView): " + safe);
                
                if (inputStr !== "[Binary Data]") {
                    console.log("   Plaintext Body: " + inputStr);
                }
                
                console.log("   Algo: " + algo + " | IV: " + ctx.iv);
                console.log("   Key: " + ctx.keyB64);
                console.log("   Output (reqBody Candidate): " + toBase64(output));
            }
        }
    } catch(e) { console.log("Cipher Hook Error: " + e); }
    
    // ================== EXTENDED HASHING TRACER (HMAC & MessageDigest) ==================
    
    // ================== EXTENDED HASHING TRACER (HMAC & MessageDigest) ==================
    
    // Unified Helper Functions
    function appendData(instance, bytes) {
        if (!instance._data) instance._data = [];
        if (bytes) {
            var jsBytes = [];
            for(var i=0; i<bytes.length; i++) jsBytes.push(bytes[i]);
            instance._data.push(jsBytes);
        }
    }

    function handleHashFinal(instance, type, output) {
        var algo = "UNKNOWN";
        try { algo = instance.getAlgorithm(); } catch(e){}
        
        // Filter out MD5 noise
        if (algo === "MD5") return;

        if (instance._data) {
            var fullStr = "";
            var fullBytes = [];
            
            instance._data.forEach(function(chunk) {
                 for(var i=0; i<chunk.length; i++) {
                     var c = chunk[i];
                     fullBytes.push(c);
                     if ((c >= 32 && c <= 126)) fullStr += String.fromCharCode(c);
                     else fullStr += ".";
                 }
            });
            
            if (fullBytes.length > 0) {
                 console.log("\n#️⃣ [" + type + "] Algo: " + algo);
                 console.log("   Input String: " + fullStr);
                 if (instance._keyInfo) console.log("   Key (Hex): " + instance._keyInfo);
                 console.log("   Result (B64): " + toBase64(output));
            }
            instance._data = null; 
        } else {
             // Print even if no input data captured, just to confirm it ran
            //  console.log("\n#️⃣ [" + type + " - No Data Capture] Algo: " + algo);
            //  if (instance._keyInfo) console.log("   Key (Hex): " + instance._keyInfo);
            //  console.log("   Result (B64): " + toBase64(output));
        }
    }

    // 1. MAC (HMAC)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        
        Mac.getInstance.overload('java.lang.String').implementation = function(algo) {
            console.log("\n⚠️ [Mac.getInstance] Requested: " + algo);
            return this.getInstance(algo);
        }

        Mac.init.overload('java.security.Key').implementation = function(key) {
             this._data = []; 
             this.init(key);
             try {
                var keyBytes = key.getEncoded();
                if (keyBytes) {
                    var k = toHex(keyBytes);
                    this._keyInfo = k;
                    console.log("\n🔑 [Mac.init] Key: " + k); 
                }
             } catch(e) { console.log("Init Key Error: " + e); }
        }
        
        // Add ByteBuffer update hook
        Mac.update.overload('java.nio.ByteBuffer').implementation = function(buffer) {
             console.log("⚠️ [Mac.update] ByteBuffer called (not fully captured)");
             this.update(buffer);
        }
        
        Mac.update.overload('byte').implementation = function(b) {
            appendData(this, [b]);
            this.update(b);
        }
        Mac.update.overload('[B').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        Mac.update.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            var slice = [];
            for(var i=off; i<off+len; i++) slice.push(b[i]);
            appendData(this, slice);
            this.update(b, off, len);
        }

        Mac.doFinal.overload().implementation = function() {
            // Print stack trace to identify caller
            console.log("   Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())); 
            var ret = this.doFinal();
            handleHashFinal(this, "HMAC", ret);
            return ret;
        }
        
        Mac.doFinal.overload('[B').implementation = function(b) {
            appendData(this, b);
            var ret = this.doFinal(b);
            handleHashFinal(this, "HMAC", ret);
            return ret;
        }

    } catch(e) { console.log("HMAC Hook Error: " + e); }

    // 2. MessageDigest (SHA-256, etc.)
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        MessageDigest.update.overload('byte').implementation = function(b) {
            appendData(this, [b]);
            this.update(b);
        }
        MessageDigest.update.overload('[B').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        MessageDigest.update.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            var slice = [];
            for(var i=off; i<off+len; i++) slice.push(b[i]);
            appendData(this, slice);
            this.update(b, off, len);
        }
        
        MessageDigest.digest.overload().implementation = function() {
            var ret = this.digest();
            handleHashFinal(this, "MD-" + this.getAlgorithm(), ret);
            return ret;
        }
        
        MessageDigest.digest.overload('[B').implementation = function(b) {
            appendData(this, b);
            var ret = this.digest(b);
            handleHashFinal(this, "MD-" + this.getAlgorithm(), ret);
            return ret;
        }

    } catch(e) { console.log("MessageDigest Hook Error: " + e); }

    // 5. Target Static Method f.l.a.m.i.a (Possible Hash Function)
    try {
        var HashUtils = Java.use("f.l.a.m.i");
        console.log("\n🎯 Attaching to f.l.a.m.i...");
        
        // Iterate all overloads of 'a'
        var methodA = HashUtils.a.overloads;
        methodA.forEach(function(ov) {
            ov.implementation = function() {
                console.log("\n[f.l.a.m.i.a] Called with " + arguments.length + " args");
                for(var i=0; i<arguments.length; i++) {
                    var arg = arguments[i];
                    var argStr = "null";
                    if (arg !== null && arg !== undefined) {
                         try { 
                             // Try to stringify if it's a String
                             argStr = arg.toString();
                             // If it looks like a byte array, show hex/safeview
                             var cls = Java.cast(arg, Java.use("java.lang.Object")).getClass().getName();
                             if (cls === "[B") {
                                 argStr = "[ByteArray] " + toBase64(arg); 
                                 // Also try to convert to string if it looks like text
                                 var safe = "";
                                 for(var j=0; j<Math.min(arg.length, 500); j++) {
                                     var c = arg[j];
                                      if ((c >= 32 && c <= 126)) safe += String.fromCharCode(c);
                                      else safe += ".";
                                 }
                                 console.log("   Arg["+i+"] (SafeView): " + safe);
                             }
                         } catch(e) { argStr = "[Object]"; }
                    }
                    console.log("   Arg[" + i + "]: " + argStr);
                }
                
                var ret = this.a.apply(this, arguments);
                if (ret !== undefined && ret !== null) {
                     try { console.log("   Ret: " + ret.toString()); } catch(e){console.log(e)}
                }
                return ret;
            }
        });
    } catch(e) { console.log("Hook f.l.a.m.i Error: " + e); }

});


// ================== NATIVE SSL HOOKS ==================
function hookSSL() {
    console.log("[*] Starting Native SSL Hooks...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }

    const targetLibs = ["stable_cronet_libssl.so", "libssl.so"];
    targetLibs.forEach(function(libName) {
        const module = Process.findModuleByName(libName);
        if (module) {
            const sslWrite = Module.findExportByName(libName, "SSL_write");
            if (sslWrite) {
                Interceptor.attach(sslWrite, {
                    onEnter: function(args) {
                        const len = args[2].toInt32();
                        if (len > 0) {
                            try {
                                const ptr = args[1];
                                // Read raw bytes
                                var data = ptr.readByteArray(len);
                                
                                // Standard HexDump (hexdump -C format)
                                function hexdump(buffer, blockSize) {
                                    blockSize = blockSize || 16;
                                    var lines = [];
                                    var hex = "0123456789ABCDEF";
                                    var u8 = new Uint8Array(buffer);
                                    
                                    for (var b = 0; b < u8.length; b += blockSize) {
                                        var block = u8.slice(b, Math.min(b + blockSize, u8.length));
                                        var addr = ("0000" + b.toString(16)).slice(-4);
                                        
                                        var hexString = "";
                                        var asciiString = "";
                                        
                                        for (var i = 0; i < block.length; i++) {
                                            var code = block[i];
                                            hexString += hex[(code >> 4) & 0x0F] + hex[code & 0x0F] + " ";
                                            asciiString += (code >= 32 && code <= 126) ? String.fromCharCode(code) : ".";
                                        }
                                        
                                        // Padding
                                        var padding = "";
                                        if (block.length < blockSize) {
                                            padding = "   ".repeat(blockSize - block.length);
                                        }
                                        
                                        lines.push(addr + "  " + hexString + padding + "  |" + asciiString + "|");
                                    }
                                    return lines.join("\n");
                                }

                                // console.log("\n🚀 [SSL_write (" + len + " bytes) from " + libName + "]:");
                                // console.log(hexdump(data));
                                
                                // FORCE PRINT SAFE TEXT
                                var safeStr = "";
                                var u8arr = new Uint8Array(data);
                                for(var i=0; i<u8arr.length; i++) {
                                    var c = u8arr[i];
                                    if( (c>=32 && c<=126) || c==10 || c==13 ) {
                                        safeStr += String.fromCharCode(c);
                                    } else {
                                        safeStr += ".";
                                    }
                                }
                                console.log("\n📄 [SSL Safe View]:\n" + safeStr);
                            } catch(e) {}
                        }
                    }
                });
            }
        }
    });
}

setTimeout(hookSSL, 1000);