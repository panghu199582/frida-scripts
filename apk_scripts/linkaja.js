/*
 * Global List Hijack (The "Doomsday" Option)
 * 
 * Strategy:
 * Hook java.util.Collections.unmodifiableList (or Arrays.asList)
 * Scan EVERY list created in the app.
 * If a list contains Protocol.H2, we NUKE it and replace it with HTTP/1.1.
 * 
 * Target: OkHttp uses Util.immutableList or Arrays.asList to set protocols.
 */

Java.perform(function() {
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    console.log("[*] ☢️ INIT: GLOBAL PROTOCOL HIJACK ACTIVE");
    console.log("[*] Warning: This hooks extremely common methods. Expect log spam or lag.");

    try {
        var Collections = Java.use("java.util.Collections");
        var Arrays = Java.use("java.util.Arrays");
        var ArrayList = Java.use("java.util.ArrayList");

        // Helper to check if a list contains H2 protocol
        function isProtocolList(list) {
            if (!list || list.size() === 0) return false;
            try {
                // Check first element type
                var item = list.get(0);
                if (!item) return false;
                var str = item.toString();
                // Standard OkHttp Protocol.toString() returns "h2", "http/1.1", etc.
                if (str === "h2" || str === "http/1.1" || str === "spdy/3.1" || str === "h2_prior_knowledge") {
                    return true;
                }
            } catch(e) {}
            return false;
        }

        // Helper: Find HTTP/1.1 Enum from the same class as the h2 enum
        function getHttp11(h2Enum) {
            try {
                var EnumClass = h2Enum.getClass();
                var methodValues = EnumClass.getMethod("values", []);
                var values = methodValues.invoke(null, []);
                for(var k=0; k<values.length; k++) {
                    var v = values[k];
                    if (v.toString() === "http/1.1" || v.toString() === "HTTP_1_1") {
                        return v;
                    }
                }
            } catch(e) {}
            return null;
        }

        // Hook 1: java.util.Collections.unmodifiableList (Used by OkHttp Builder)
        // Careful: This is called millions of times. We need a very fast check.
        Collections.unmodifiableList.overload('java.util.List').implementation = function(list) {
            if (list && list.size() > 0) {
                 // Fast check: Is it our protocols list?
                 if (isProtocolList(list)) {
                     var hasH2 = false;
                     var h2Enum = null;
                     for(var i=0; i<list.size(); i++) {
                         var s = list.get(i).toString();
                         if (s === "h2" || s === "h2_prior_knowledge") {
                             hasH2 = true;
                             h2Enum = list.get(i);
                             break;
                         }
                     }

                     if (hasH2 && h2Enum) {
                         console.log("[!] ☢️ Intercepted H2 Protocol List creation!");
                         var http11 = getHttp11(h2Enum);
                         if (http11) {
                             console.log("    -> Replaced with [HTTP/1.1]");
                             // Return a new list with only HTTP/1.1
                             var newList = ArrayList.$new();
                             newList.add(http11);
                             return this.unmodifiableList(newList);
                         }
                     }
                 }
            }
            return this.unmodifiableList(list);
        };

        // Hook 2: Arrays.asList (Commonly used to create protocol lists)
        Arrays.asList.overload('[Ljava.lang.Object;').implementation = function(arr) {
            if (arr && arr.length > 0) {
                var hasH2 = false;
                var h2Enum = null;
                var http11Enum = null;
                
                for(var i=0; i<arr.length; i++) {
                    var item = arr[i];
                    if (item) {
                        var s = item.toString();
                        if (s === "h2" || s === "h2_prior_knowledge") {
                            hasH2 = true;
                            h2Enum = item;
                        } else if (s === "http/1.1" || s === "HTTP_1_1") {
                            http11Enum = item;
                        }
                    }
                }

                if (hasH2) {
                    // console.log("[!] ☢️ Intercepted H2 in Arrays.asList!");
                    if (http11Enum) {
                         // Create new array with only http/1.1
                         // Make sure type matches
                         var newArr = Java.array("java.lang.Object", [http11Enum]); 
                         // Note: We need to cast back to specific Enum array type if possible, 
                         // but Arrays.asList takes Object[], so this might pass.
                         // However, if the caller expects List<Protocol>, returning List<Object> is fine in Java runtime (erasure),
                         // but standard Java.array creates specific type.
                         
                         // Safer: Just modify the input array in place? No, unsafe.
                         // Let's call original with new array.
                         return this.asList(newArr);
                    } else if (h2Enum) {
                        // Try to find http11 from h2Enum class
                         var http11 = getHttp11(h2Enum);
                         if (http11) {
                             var newArr = Java.array("java.lang.Object", [http11]);
                             return this.asList(newArr);
                         }
                    }
                }
            }
            return this.asList(arr);
        };
        
        // Hook 3: MessageDigest for SHA-256 Analysis
        var MessageDigest = Java.use("java.security.MessageDigest");
        var Base64 = Java.use("android.util.Base64");
        
        MessageDigest.digest.overload().implementation = function() {
            var ret = this.digest();
            handleDigest(this, ret);
            return ret;
        }
        MessageDigest.digest.overload('[B').implementation = function(b) {
            this.update(b); 
            var ret = this.digest();
            handleDigest(this, ret);
            return ret;
        }
        
        function handleDigest(instance, match) {
           try {
               var algo = instance.getAlgorithm();
               if (algo === "SHA-256") {
                //    console.log("\n#️⃣ [MessageDigest] SHA-256 Calculated");
                   // We can't see the input length easily without hooking update, 
                   // but we can check the result.
                   var b64 = Base64.encodeToString(match, 2); // NO_WRAP
                //    console.log("   Result: " + b64);
                   
                   // Compare with the target if known or just print
                   // If we hooked update we could see size. Let's hook update too quickly? 
                   // No, keep it simple first to avoid breaking.
               }
           } catch(e) {}
        }
        
        // Hook 4: MessageDigest Update to detect large files (Image)
        MessageDigest.update.overload('[B').implementation = function(b) {
            this.update(b);
            try {
                if (b.length > 10000 && this.getAlgorithm() === "SHA-256") {
                //     console.log("\n📸 [SHA-256] Large Update detected! (" + b.length + " bytes) - Likely Image Hashing");
                }
            } catch(e) {}
        }
        MessageDigest.update.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            this.update(b, off, len);
             try {
                if (len > 10000 && this.getAlgorithm() === "SHA-256") {
                    //  console.log("\n📸 [SHA-256] Large Update detected! (" + len + " bytes) - Likely Image Hashing");
                }
            } catch(e) {}
        }


        // Hook 5: Headers Builder to trace the header source
        try {
            var HeadersBuilder = Java.use("okhttp3.Headers$Builder");
            HeadersBuilder.add.overload('java.lang.String', 'java.lang.String').implementation = function(name, value) {
                if (name.toLowerCase() === "sha-256-digest") {
                //    console.log("\n🎯 [GlobalHijack] Found SHA-256-DigestHeader!");
                //    console.log("   Value: " + value);
                //    console.log("   Trace: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                }
                return this.add(name, value);
            }
        } catch(e) { console.log("[-] Headers hook error: " + e); }

    } catch(e) {
        console.log("[-] Hook Error: " + e);
    }
});

// Also include the existing monitoring for verification

// --- Stack Trace Discovery (To Find Obfuscated RealCall) ---
Java.perform(function() {
    try {
        var Socket = Java.use("java.net.Socket");
        var hasPrinted = false;

        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            if (!hasPrinted) {
                console.log("\n� [Socket] Connecting to: " + endpoint.toString());
                console.log("    (Analyzing Stack Trace to find RealCall...)");
                
                var trace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                console.log(trace);
                
                hasPrinted = true; // Only print once to avoid spam
                console.log("[-] 🛑 Check the log above. Look for the class calling 'ConnectInterceptor' or 'RealCall'."); 
            }
            return this.connect(endpoint, timeout);
        }
        console.log("[+] 🕵️ Stack Trace Discovery Active (Trigger an action in the app!)");
    } catch(e) {
        console.log("[-] Socket Hook Error: " + e);
    }
});
// --- Advanced Native SSL Hook (Full Traffic + Context) ---
setTimeout(function() {
    var lib = "libssl.so";
    if (!Module.findExportByName(lib, "SSL_write")) {
        lib = "libmonochrome.so"; 
        if (!Module.findExportByName(lib, "SSL_write")) lib = "libcrypto.so"; 
    }

    var ssl_write = Module.findExportByName(lib, "SSL_write");
    var ssl_read = Module.findExportByName(lib, "SSL_read");
    var contextMap = {};

    function cleanStr(data, len) {
        var u8 = new Uint8Array(data);
        var str = "";
        // Read up to decent length to capture full headers/bodies
        var max = Math.min(len, 32768); 
        for(var i=0; i<max; i++) {
            var c = u8[i];
            // Allow tab, newline, carriage return, and printable ASCII
            if((c>=32&&c<=126)||c==10||c==13||c==9) str+=String.fromCharCode(c);
            else str+="."; 
        }
        return str;
    }

    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(args) {
                var sslPtr = args[0].toString();
                var len = args[2].toInt32();
                if (len > 0) {
                    var data = args[1].readByteArray(len);
                    var str = cleanStr(data, len);

                    // 1. Analyze Context (Method/URL)
                    var methodMatch = str.match(/^(GET|POST|PUT|DELETE|PATCH) ([^ ]+) HTTP/);
                    if (methodMatch) {
                        contextMap[sslPtr] = { 
                            method: methodMatch[1], 
                            path: methodMatch[2], 
                            host: "unknown",
                            fullUrl: null
                        };
                    }
                    var hostMatch = str.match(/Host: ([^\r\n]+)/i);
                    if (hostMatch && contextMap[sslPtr]) {
                        contextMap[sslPtr].host = hostMatch[1].trim();
                        contextMap[sslPtr].fullUrl = "https://" + contextMap[sslPtr].host + contextMap[sslPtr].path;
                    }

                    // 2. Prepare Log Prefix
                    var prefix = "[SSL Outgoing]";
                    if (contextMap[sslPtr]) {
                        if (contextMap[sslPtr].fullUrl) prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].fullUrl + "]";
                        else prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].path + "]";
                    }

                    // 3. Log Content
                    // If it looks like a new Request (has Method line), log as Headers
                    if (methodMatch) {
                        console.log("\n🚀 " + prefix + " Request Headers/Body:\n" + str);
                    } else {
                        // Otherwise it's likely a Body chunk (JSON, Form, etc)
                        // Only log if it has meaningful content
                        if (str.replace(/\./g, "").trim().length > 0) {
                             console.log("\n📤 " + prefix + " Request Body Chunk:\n" + str);
                        }
                    }
                }
            }
        });
    }

    if (ssl_read) {
        Interceptor.attach(ssl_read, {
            onEnter: function(args) {
                this.sslPtr = args[0].toString();
                this.buf = args[1];
            },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 0 && this.buf) {
                    var data = this.buf.readByteArray(len);
                    var str = cleanStr(data, len);
                    
                    var ctx = contextMap[this.sslPtr];
                    var prefix = ctx ? ("[" + ctx.method + " " + (ctx.fullUrl || ctx.path) + "]") : "[SSL Response]";

                    // Check if it's Headers or Body
                    if (str.startsWith("HTTP/1.1") || str.startsWith("HTTP/2")) {
                        console.log("\n⬅️ " + prefix + " Response Headers:\n" + str);
                    } else {
                        // Body chunk
                        if (str.replace(/\./g, "").trim().length > 0) {
                             console.log("\n⬇️ " + prefix + " Response Body Chunk:\n" + str);
                        }
                    }
                }
            }
        });
    }
    
    console.log("[+] 🛡️ Native SSL Monitoring Active (Full Traffic + URL Context)");
}, 1000);

// --- Universal Response Decompression (GZIP + Inflater) ---
Java.perform(function() {
    try {
        function hookDecompressor(className, methodName) {
            try {
                var Clazz = Java.use(className);
                var StringClass = Java.use("java.lang.String");
                var Charset = Java.use("java.nio.charset.Charset");
                var utf8 = Charset.forName("UTF-8");

                var overloads = Clazz[methodName].overloads;
                for (var i = 0; i < overloads.length; i++) {
                    overloads[i].implementation = function() {
                        var ret = this[methodName].apply(this, arguments);
                        if (ret > 0) {
                            try {
                                var buffer = arguments[0];
                                var offset = 0;
                                var len = ret;
                                if (arguments.length >= 3 && typeof arguments[1] === 'number') {
                                    offset = arguments[1];
                                }
                                
                                if (buffer && buffer.length > 0) {
                                    var s = StringClass.$new(buffer, offset, len, utf8).toString();
                                    // Removed strict JSON start check to allow chunks
                                    // Simple heuristic: if it has some length and printable chars
                                    if (s.length > 2) {
                                         // Filter out binary noise if needed, or just print everything that looks like text
                                         // Check for common JSON chars
                                         if (s.includes('"') || s.includes(':') || s.includes('{') || s.includes('[')) {
                                             console.log("\n⬇️ [RES-BODY-CHUNK] (" + className + ", " + len + "b):\n" + s);
                                         }
                                    }
                                }
                            } catch(e) {}
                        }
                        return ret;
                    }
                }
            } catch(e) { }
        }

        // 1. Hook Streams
        hookDecompressor("java.util.zip.GZIPInputStream", "read");
        hookDecompressor("java.util.zip.InflaterInputStream", "read");
        
        // 2. Hook Raw Inflater (OkHttp often uses this internally)
        try {
            var Inflater = Java.use("java.util.zip.Inflater");
            // inflate(byte[] b, int off, int len)
            Inflater.inflate.overload('[B', 'int', 'int').implementation = function(b, off, len) {
                var ret = this.inflate(b, off, len);
                if (ret > 0) {
                    try {
                        var StringClass = Java.use("java.lang.String");
                        var s = StringClass.$new(b, off, ret, Java.use("java.nio.charset.Charset").forName("UTF-8")).toString();
                        // Relaxed filter for chunks
                        if (s.length > 2 && (s.includes('"') || s.includes(':') || s.includes('{'))) {
                             console.log("\n⬇️ [RES-BODY-CHUNK] (Inflater, " + ret + "b):\n" + s);
                        }
                    } catch(e) {}
                }
                return ret;
            }
        } catch(e) {}

        console.log("[+] 📦 Universal Response Logger Active (Plaintext Chunks)");
    } catch(e) { 
        console.log("[-] Universal Hook Error: " + e); 
    }
});
