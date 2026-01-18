/*
 * Pgbank Analysis - Targeted OkHttp/Retrofit Hooks (o.w, o.r)
 */

// ================== UTILS ==================
function readStdString(ptr, len) {
    try {
        if (len <= 0) return "";
        const snippet = ptr.readByteArray(Math.min(len, 4));
        const u8 = new Uint8Array(snippet);
        // Check for GZIP or Binary
        if (u8[0] === 0x1f && u8[1] === 0x8b) return "[GZIP Data]";
        if (u8[0] < 0x20 && u8[0] !== 0x09 && u8[0] !== 0x0a && u8[0] !== 0x0d) return "[Binary Data]";

        const readLen = Math.min(len, 32768); 
        return ptr.readUtf8String(readLen);
    } catch (e) { return "" }
}

// ================== JAVA HOOKS ==================
Java.perform(function() {
    var StringClass = Java.use("java.lang.String");
    var Charset = Java.use("java.nio.charset.Charset");
    var utf8 = Charset.forName("UTF-8");
    var ProxyClass = Java.use("java.lang.reflect.Proxy");
    var ObjectClass = Java.use("java.lang.Object");

    // ================== HELPER FUNCTIONS ==================
    function isReadable(str) {
        if (!str || str.length === 0) return false;
        var len = Math.min(str.length, 50);
        var readableCount = 0;
        for (var i = 0; i < len; i++) {
            var c = str.charCodeAt(i);
            if ((c >= 32 && c <= 126) || c === 10 || c === 13) {
                readableCount++;
            }
        }
        return (readableCount / len) > 0.8;
    }

    function toHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        var len = Math.min(bytes.length, 64);
        for(var i=0; i<len; i++) {
            var b = bytes[i] & 0xFF;
            if (b < 16) hex += "0";
            hex += b.toString(16);
        }
        return hex + (bytes.length > 64 ? "..." : "");
    }
    // ======================================================

    // Helper: Deep Inspect Java Objects (Reflection)
    function inspectObject(obj, depth) {
        // ... (rest of inspectObject logic) ...
        if (depth === undefined) depth = 0;
        if (depth > 5) return "..."; 
        if (obj === null || obj === undefined) return "null";
        
        try {
            var javaObj = Java.cast(obj, ObjectClass);
            var cls = javaObj.getClass();
            var clsName = cls.getName();
            var str = "[" + clsName + "]@" + javaObj.hashCode().toString(16);
            return str;
            // ... (rest of inspect logic, simplified here) ...
        } catch(e) { return "[Inspect Error]: " + e; }
    }


    // 5. Hash Monitor (Smart Tracer)
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        // Helper to reconstruct string from chunks
        function reconstructString(chunks) {
            var str = "";
            chunks.forEach(function(chunk) {
                for(var i=0; i<Math.min(chunk.length, 2048); i++) {
                    var c = chunk[i];
                    if( (c>=32 && c<=126) || c==10 || c==13 ) str += String.fromCharCode(c);
                    else str += ".";
                }
            });
            return str;
        }

        // Hook digest(...)
        // Logic: specific matching for "Body-Like" signatures
        
        MessageDigest.update.overload('[B').implementation = function(bytes) {
            this.update(bytes);
            if (!this._data) this._data = [];
            
            // Store slice
            var jsBytes = [];
            var len = Math.min(bytes.length, 4096); 
            for(var i=0; i<len; i++) jsBytes.push(bytes[i]);
            this._data.push(jsBytes);
            
            // Check for potential signature
            var checkStr = "";
            for(var i=0; i<Math.min(len, 100); i++) checkStr += String.fromCharCode(bytes[i]);
            
            // Heuristic: If we see something that looks like our Encrypted Body Base64
            // (e.g. alphanumeric, +, /, and long)
            // Or matches a known substring from previous logs if consistent.
            // Let's just track everything and filter at digest time.
        }
        
        MessageDigest.update.overload('[B', 'int', 'int').implementation = function(bytes, off, len) {
            this.update(bytes, off, len);
            if (!this._data) this._data = [];
            var jsBytes = [];
            var end = Math.min(off + len, bytes.length);
            for(var i=off; i<end; i++) jsBytes.push(bytes[i]);
            this._data.push(jsBytes);
        }

        function handleDigest(instance, result) {
            var hex = toHex(result);
            if (instance._data) {
                var inputStr = reconstructString(instance._data);
                
                // INTELLIGENT FILTER:
                // If input contains a long Base64-like string or JSON chars
                // We specifically look for the encrypted body pattern seen in logs
                // OR just print if it's long enough to be interesting.
                
                // Let's filter for the presence of the Encrypted Body we saw earlier '1y8fLGKn' or generic long tokens
                // Or simply print ANY SHA-256 that has input > 100 bytes.
                
                if (inputStr.length > 50) {
                     console.log("\n🎯 [SHA-256 Input] Hash: " + hex);
                     console.log("   Preview: " + inputStr.substring(0, 100) + "...");
                     console.log("   >>> FULL INPUT <<<");
                     console.log(inputStr);
                     console.log("   >>> END INPUT <<<");
                }
            }
            instance._data = [];
        }

        // Hook digest()
        MessageDigest.digest.overload().implementation = function() {
            var ret = this.digest();
            handleDigest(this, ret);
            return ret;
        }
        
        // Hook digest(byte[])
        MessageDigest.digest.overload('[B').implementation = function(input) {
            if (!this._data) this._data = [];
            var jsBytes = [];
            for(var i=0; i<input.length; i++) jsBytes.push(input[i]);
            this._data.push(jsBytes);
            var ret = this.digest(input);
            handleDigest(this, ret);
            return ret;
        }
        
    // 9. Trace Target Class f.l.a.k.i
    try {
        var TargetClass = Java.use("f.l.a.k.i");
        var methods = TargetClass.class.getDeclaredMethods();
        
        console.log("\n🕵️ Tracing f.l.a.k.i methods...");
        
        methods.forEach(function(m) {
            var methodName = m.getName();
            var overloads = TargetClass[methodName].overloads;
            
            overloads.forEach(function(ov) {
                ov.implementation = function() {
                    console.log("\n👉 [f.l.a.k.i." + methodName + "] Called");
                    
                    // INSPECT FIELDS OF 'THIS'
                    try {
                        console.log("   [Fields of this]:\n" + inspectObject(this, 1));
                    } catch(e) { console.log("   [Field Inspect Error]: " + e); }

                    // Log Arguments
                    for (var i = 0; i < arguments.length; i++) {
                        var arg = arguments[i];
                        var argStr = "null";
                        if (arg !== null) {
                            try { argStr = arg.toString(); } catch(e){}
                            try { 
                                if (arg.getClass().getName() === "[B") {
                                    argStr = "[Bytes] " + toHex(arg) + "\n(String): " + StringClass.$new(arg).toString();
                                }
                            } catch(e){}
                        }
                        console.log("   Arg[" + i + "]: " + argStr);
                    }
                    var ret = this[methodName].apply(this, arguments);
                    return ret;
                }
            });
        });
    } catch(e) { console.log("Trace Error: " + e); }

    // 10. Trace HMAC All Operations (Capture Full Input)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        
        // Helper to append data
        function appendData(instance, bytes) {
            if (!instance._data) instance._data = [];
            if (bytes) {
                var jsBytes = [];
                for(var i=0; i<bytes.length; i++) jsBytes.push(bytes[i]);
                instance._data.push(jsBytes);
            }
        }
        
        function dumpMacInput(instance) {
            if (instance._data) {
                // Reconstruct
                var str = "";
                var hex = "";
                var totalLen = 0;
                
                instance._data.forEach(function(chunk) {
                    totalLen += chunk.length;
                    for(var i=0; i<chunk.length; i++) {
                        var c = chunk[i];
                        if( (c>=32 && c<=126) || c==10 || c==13 ) str += String.fromCharCode(c);
                        else str += ".";
                        
                        if (totalLen < 64) {
                            var h = (c & 0xFF).toString(16);
                            if(h.length<2) h="0"+h;
                            hex += h;
                        }
                    }
                });
                
                console.log("\n🔑 [HMAC Final] Algo: " + instance.getAlgorithm());
                console.log("   Full Input String (" + totalLen + " bytes):");
                console.log("   👉 " + str);
                console.log("   (Hex start): " + hex);
                
                instance._data = []; // clear
            }
        }

        Mac.init.overload('java.security.Key').implementation = function(key) {
            this._data = []; // reset
            return this.init(key);
        }
        
        Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(key, spec) {
             this._data = []; // reset
             return this.init(key, spec);
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
            // slice
            var slice = [];
            for(var i=off; i<off+len; i++) slice.push(b[i]);
            appendData(this, slice);
            this.update(b, off, len);
        }
        
        Mac.update.overload('java.nio.ByteBuffer').implementation = function(buf) {
            // This is harder to peek without draining, let's skip for now or try to peek
            console.log("🔑 [HMAC Update] ByteBuffer called (Input not captured)");
            this.update(buf);
        }

        var Base64 = Java.use("android.util.Base64");

        Mac.doFinal.overload().implementation = function() {
            dumpMacInput(this);
            var ret = this.doFinal();
            console.log("   = Result (Base64): " + Base64.encodeToString(ret, 2)); // NO_WRAP
            return ret;
        }
        
        Mac.doFinal.overload('[B').implementation = function(b) {
            appendData(this, b);
            dumpMacInput(this);
            var ret = this.doFinal(b);
            console.log("   = Result (Base64): " + Base64.encodeToString(ret, 2));
            return ret;
        }
        
    } catch(e) { console.log("HMAC Hook Error: " + e); }
    } catch(e) { console.log("Hash Hook Error: " + e); }


});

// ================== NATIVE SSL HOOKS ==================
function hookSSL() {
    console.log("[*] Starting Native SSL Hooks...");
    
    // ... Simplified SSL hooks ...
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

                                // Try string for readability (Optional)
                                // var str = ptr.readUtf8String(Math.min(len, 1024));
                                // // if (str && (str.indexOf("HTTP")!==-1 || str.indexOf("POST")!==-1)) {
                                // //     console.log("   [Text View]:\n" + str);
                                // // }
                                // console.log("susscee")
                                // console.log(ptr.toString());
                                
                                console.log("\n🚀 [SSL_write (" + len + " bytes) from " + libName + "]:");
                                console.log(hexdump(data));
                                
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