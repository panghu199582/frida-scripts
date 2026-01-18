/*
 * Native SSL/TLS Monitor (HTTP/1.1 Focus) - UTF-8 Enhanced
 * Hooks low-level SSL_write and SSL_read to capture decrypted traffic.
 * Uses Java String decoding to correctly display Vietnamese/UTF-8 characters.
 * 
 * Usage: frida -U -f <package> -l native_ssl_monitor.js
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
    console.log("[*] Initializing Native SSL Monitor (UTF-8 Enabled)...");

    // ===========================================
    // 1. GLOBAL HTTP/2 DOWNGRADE LOGIC
    // ===========================================
    try {
        var Collections = Java.use("java.util.Collections");
        var Arrays = Java.use("java.util.Arrays");
        var ArrayList = Java.use("java.util.ArrayList");

        function isProtocolList(list) {
            if (!list || list.size() === 0) return false;
            try {
                var item = list.get(0);
                if (!item) return false;
                var str = item.toString();
                if (str === "h2" || str === "http/1.1" || str === "spdy/3.1" || str === "h2_prior_knowledge") {
                    return true;
                }
            } catch(e) {}
            return false;
        }

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

        Collections.unmodifiableList.overload('java.util.List').implementation = function(list) {
            if (list && list.size() > 0) {
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
                             var newList = ArrayList.$new();
                             newList.add(http11);
                             return this.unmodifiableList(newList);
                         }
                     }
                 }
            }
            return this.unmodifiableList(list);
        };

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
                    if (http11Enum) {
                         var newArr = Java.array("java.lang.Object", [http11Enum]); 
                         return this.asList(newArr);
                    } else if (h2Enum) {
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
    } catch(e) { console.log("[-] Downgrade Hook Error: " + e); }

    // ===========================================
    // 2. NATIVE MONITORING LOGIC
    // ===========================================

    var StringClass = Java.use("java.lang.String");
    var Charset = Java.use("java.nio.charset.Charset");
    var UTF8 = Charset.forName("UTF-8");

    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
    var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var BufferedReader = Java.use("java.io.BufferedReader");

    // FILE IO
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var File = Java.use("java.io.File");

    function appendToFile(tid, dataPtr, dataLen) {
        try {
            var fileName = "/sdcard/Download/ssl_intercept_" + tid + ".bin";
            var file = File.$new(fileName);
            var fos = FileOutputStream.$new(file, true); // Append mode
            
            var buf = dataPtr.readByteArray(dataLen);
            // Convert to Java Byte Array
            var u8 = new Uint8Array(buf);
            var jArr = Java.array('byte', u8); // Auto-conversion usually works in recent Frida, otherwise manual loop needed
            
            fos.write(jArr);
            fos.flush();
            fos.close();
            return fileName;
        } catch(e) {
            console.log("[File Write Error]: " + e);
            return null;
        }
    }

    function decompressGzip(jBytes) {
        try {
            var bis = ByteArrayInputStream.$new(jBytes);
            var gis = GZIPInputStream.$new(bis);
            var reader = InputStreamReader.$new(gis, UTF8);
            var buffered = BufferedReader.$new(reader);
            var sb = Java.use("java.lang.StringBuilder").$new();
            var line;
            while ((line = buffered.readLine()) !== null) {
                sb.append(line);
                sb.append("\n");
            }
            return sb.toString();
        } catch(e) {
            return "[GZIP Decompress Failed]";
        }
    }

    function safeString(ptr, len) {
        if (len <= 0) return { str: "", isBinary: false };
        if (len > 1024 * 1024) return { str: "[Too Large to Decode]", isBinary: true }; 

        try {
            var buf = ptr.readByteArray(len);
            var u8 = new Uint8Array(buf);

            // 1. Check for Double CRLF (\r\n\r\n) to split Headers and Body
            var splitIndex = -1;
            for(var i=0; i<Math.min(len, 8192); i++) {
                if (u8[i]===13 && u8[i+1]===10 && u8[i+2]===13 && u8[i+3]===10) {
                    splitIndex = i;
                    break;
                }
            }

            var headerStr = "";
            var bodyStr = "";
            
            function toJavaBytes(u8Data) {
                var javaBytes = [];
                for (var i = 0; i < u8Data.length; i++) {
                    var b = u8Data[i];
                    if (b > 127) b = b - 256;
                    javaBytes.push(b);
                }
                return Java.array('byte', javaBytes);
            }

            if (splitIndex !== -1) {
                // Case A: Headers + Body
                var headerBytes = u8.slice(0, splitIndex + 4);
                var bodyBytes = u8.slice(splitIndex + 4);
                
                headerStr = StringClass.$new(toJavaBytes(headerBytes), UTF8).toString();
                
                if (bodyBytes.length > 0) {
                    // Check for GZIP Magic (1F 8B)
                    if (bodyBytes.length >= 2 && bodyBytes[0] === 0x1F && bodyBytes[1] === 0x8B) {
                        bodyStr = "\n[GZIP Decompressed]:\n" + decompressGzip(toJavaBytes(bodyBytes));
                    } else {
                        bodyStr = StringClass.$new(toJavaBytes(bodyBytes), UTF8).toString();
                        if (bodyStr.indexOf("\uFFFD") !== -1 && bodyBytes.length > 50) {
                             bodyStr = "[Binary Body / Image Data] (" + bodyBytes.length + " bytes)";
                        }
                    }
                }
            } else {
                // Case B: Chunk
                if (u8.length >= 2 && u8[0] === 0x1F && u8[1] === 0x8B) {
                    headerStr = "";
                    bodyStr = "\n[GZIP Decompressed Chunk]:\n" + decompressGzip(toJavaBytes(u8));
                } else {
                    headerStr = StringClass.$new(toJavaBytes(u8), UTF8).toString();
                }
            }

            return { str: headerStr + bodyStr, isBinary: false };

        } catch(e) { 
            return { str: "[Decode Error: " + e + "]", isBinary: true }; 
        }
    }

    function bufToHex(ptr, len) {
        try {
            if (len <= 0) return "";
            // Read up to 100KB
            var buf = ptr.readByteArray(Math.min(len, 102400)); 
            var u8 = new Uint8Array(buf);
            var hex = "";
            for (var i = 0; i < u8.length; i++) {
                var val = u8[i];
                if (val < 16) hex += "0";
                hex += val.toString(16);
            }
            return hex;
        } catch(e) { return "[Hex Error: " + e + "]"; }
    }

    var blockingState = {}; // Map<ThreadId, Boolean>

    const commmonLibs = [
        "libssl.so", 
        "libboringssl.so", 
        "libnetwork.so", 
        "libcronet.so"
    ];

    var hooked = false;

    commmonLibs.forEach(function(libName) {
        var mod = Process.findModuleByName(libName);
        if (!mod) return;

        console.log("[+] Found Library: " + libName);

        // --- SSL_write (Requests) ---
        var symbolWrite = Module.findExportByName(libName, "SSL_write");
        if (symbolWrite) {
            console.log("    -> Hooking SSL_write");
            hooked = true;
            Interceptor.attach(symbolWrite, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    var tid = Process.getCurrentThreadId();
                    
                    if (len > 0) {
                        // 1. Prepare Data
                        var parsed = safeString(args[1], len);
                        var rawHex = bufToHex(args[1], len); // Ensure this is defined!
                        
                        // 2. Persistent Blocking Logic
                        if (parsed.str.indexOf("liveness-face-matching") !== -1) {
                            console.log("\n👀 [TARGET DETECTED] Header found in Thread " + tid);
                            console.log("---------------------------------------------------------------");
                            console.log(parsed.str);
                            
                            // 1. Prepare File for Dump
                            var fPath = "/sdcard/Download/ssl_intercept_" + tid + ".bin";
                            var f = File.$new(fPath);
                            if (f.exists()) f.delete();
                            
                            console.log("   -> 📂 [FILE] Started new binary dump: " + fPath);
                            
                            blockingState[tid] = { count: 0, totalBytes: 0, filePath: fPath };
                            return; // Allow Header
                        }

                        if (blockingState[tid]) {
                             var state = blockingState[tid];
                             state.count++;
                             state.totalBytes += len;
                             
                             console.log("\n💾 [SAVING] Chunk #" + state.count + " (" + len + " bytes)");
                             
                             // 2. Save Chunk to File
                             appendToFile(tid, args[1], len);
                             
                             // 3. Log Console Preview (First 5 chunks)
                             if (state.count <= 5) {
                                 console.log("[Body Chunk Raw Hex]: " + rawHex.substring(0, 100) + "...");
                             } else if (state.count === 6) {
                                 console.log("   ... (Suppressing further logs, writing to file) ...");
                             }
                             
                             // args[2] = ptr(0); // DISABLE BLOCKING
                             return;
                        }

                        // 3. General Logging (Non-Blocked)
                        // OPTIMIZATION: Silence standard logs to prevent lag. ONLY log blocked target.
                        /*
                        if (!parsed.isBinary && (parsed.str.match(/^(GET|POST|PUT|DELETE) /) || parsed.str.includes("HTTP/1"))) {
                            console.log("\n⬆️ [SSL Request] (" + len + " bytes)");
                            console.log(parsed.str.substring(0, 1000));
                            // console.log("[Raw Hex]: " + rawHex.substring(0, 2000) + (rawHex.length>2000?"...":""));
                        }
                        */
                        if (!parsed.isBinary) {
                            if (parsed.str.match(/^(GET|POST|PUT|DELETE) /) || parsed.str.includes("HTTP/1")) {
                                console.log("\n⬆️ [SSL Request] (" + len + " bytes) ------------------------");
                                console.log(parsed.str);
                                console.log("---------------------------------------------------------------");
                            }
                        } else {
                            // console.log("\n⬆️ [SSL Request Binary] (" + len + " bytes)");
                        }
                    }
                }
            });
        }

        // --- SSL_read (Responses) ---
        var symbolRead = Module.findExportByName(libName, "SSL_read");
        if (symbolRead) {
            console.log("    -> Hooking SSL_read");
            hooked = true;
            Interceptor.attach(symbolRead, {
                onEnter: function(args) {
                    this.bufPtr = args[1];
                },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && this.bufPtr) {
                        var parsed = safeString(this.bufPtr, len);
                        
                        if (!parsed.isBinary) {
                            var clean = parsed.str.trim();
                            if (clean.startsWith("HTTP/1") || clean.includes(": ")) {
                                console.log("\n⬇️ [SSL Response] (" + len + " bytes) -----------------------");
                                console.log(parsed.str);
                                console.log("---------------------------------------------------------------");
                            } else if (clean.startsWith("{") || clean.startsWith("[")) {
                                 console.log("\n⬇️ [SSL Response Body] (" + len + " bytes):");
                                 console.log(parsed.str);
                            }
                        }
                    }
                }
            });
        }
    });

    if (!hooked) {
        console.log("[-] No standard SSL libraries found.");
    } else {
        console.log("[*] UTF-8 Monitor Active.");
    }
});
