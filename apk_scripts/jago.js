/*
 * Jago App Hook Script
 * Based on linkaja.js structure
 * Features:
 * 1. Anti-Detection (Developer Mode, ADB, Debugging)
 * 2. Global Protocol Hijack (HTTP/2 -> HTTP/1.1)
 * 3. Native SSL Logging (Read/Write)
 * 4. Response Decompression
 */

// ============================================================================
// 🛡️ 1. Anti-Detection (Developer Mode / ADB / USB Debugging)
// ============================================================================
Java.perform(function() {
    console.log("[*] 🛡️ ACTIVATING ANTI-DETECTION MODULE...");

    try {
        var SettingsSecure = Java.use("android.provider.Settings$Secure");
        var SettingsGlobal = Java.use("android.provider.Settings$Global");
        var Debug = Java.use("android.os.Debug");

        // Helper to handle checks
        function handleSetting(name, originalVal) {
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                console.log("    [!] 🛡️ Bypassing detection for: " + name);
                return 0; // Force False
            }
            return originalVal;
        }

        // Hook Settings.Secure.getInt
        SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            var ret = this.getInt(cr, name);
            return handleSetting(name, ret);
        };
        SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            var ret = this.getInt(cr, name, def);
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                console.log("    [!] 🛡️ Bypassing detection for: " + name);
                return 0;
            }
            return ret;
        };

        // Hook Settings.Global.getInt
        SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            var ret = this.getInt(cr, name);
            return handleSetting(name, ret);
        };
        SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            var ret = this.getInt(cr, name, def);
            if (name === "adb_enabled" || name === "development_settings_enabled") {
                console.log("    [!] 🛡️ Bypassing detection for: " + name);
                return 0;
            }
            return ret;
        };

        // Hook Debug.isDebuggerConnected
        Debug.isDebuggerConnected.implementation = function() {
            console.log("    [!] 🛡️ Bypassing Debug.isDebuggerConnected check");
            return false;
        };

        console.log("[+] 🛡️ Anti-Detection Hooks Applied!");

    } catch (e) {
        console.log("[-] Anti-Detection Error: " + e);
    }

    /*
    // --- B. Native Layer Hooks (ptrace, maps, status) ---
    // DISABLED: EverSafe detects these hooks (integrity check) and crashes the app.
    
    // 1. Bypass ptrace(PTRACE_TRACEME)
    var ptrace = Module.findExportByName(null, "ptrace");
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
            if (request == 0) return 0;
            return 0; 
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
    }

    // 2. Bypass TracerPid in /proc/self/status
    var fopen = Module.findExportByName(null, "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.path = args[0].readCString();
                if (this.path.indexOf("/proc/") >= 0 && this.path.indexOf("/status") >= 0) {
                    this.isStatus = true;
                }
            },
            onLeave: function(retval) { }
        });
    }
    
    // 3. Hook fgets to scrub TracerPid
    var fgets = Module.findExportByName(null, "fgets");
    if (fgets) {
         Interceptor.attach(fgets, {
            onEnter: function(args) { this.buf = args[0]; },
            onLeave: function(retval) {
                if (retval.isNull()) return;
                try {
                    var content = retval.readCString();
                    if (content.indexOf("TracerPid:") >= 0) {
                        var val = content.split(":")[1].trim();
                        if (val !== "0") {
                            var newContent = "TracerPid:\t0\n";
                            this.buf.writeUtf8String(newContent);
                        }
                    }
                } catch(e) {}
            }
         });
    }

    // --- C. Multi-Process / Fork Hook (Anti-Guard) ---
    var fork = Module.findExportByName(null, "fork");
    function hookFork(symbol) {
        if (symbol) {
             Interceptor.attach(symbol, {
                onLeave: function(retval) { }
            });
        }
    }
    hookFork(fork);

    // --- D. Anti-Suicide (Native Exit) ---
    var exitPtr = Module.findExportByName(null, "exit");
    var underscoreExitPtr = Module.findExportByName(null, "_exit");
    var killPtr = Module.findExportByName(null, "kill");
    var raisePtr = Module.findExportByName(null, "raise");

    function preventExit(name, ptr) {
        if (ptr) {
            Interceptor.replace(ptr, new NativeCallback(function(arg) { }, 'void', ['int']));
        }
    }
    // preventExit("exit", exitPtr); 
    
    if (killPtr) {
        Interceptor.replace(killPtr, new NativeCallback(function(pid, sig) {
            return 0; 
        }, 'int', ['int', 'int']));
    }
    
    if (raisePtr) {
        Interceptor.replace(raisePtr, new NativeCallback(function(sig) {
             return 0;
        }, 'int', ['int']));
    }
    */

    console.log("[+] 🛡️ Java Anti-Detection Hooks Applied Only (Native Hooks Disabled for Stability)");
});

// ============================================================================
// ☢️ 2. Global Protocol Hijack (Force HTTP/1.1)
// ============================================================================
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
                         // console.log("[!] ☢️ Intercepted H2 Protocol List creation!");
                         var http11 = getHttp11(h2Enum);
                         if (http11) {
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
    } catch(e) {
        console.log("[-] Protocol Hijack Error: " + e);
    }
});

// ============================================================================
// 🕵️ 3. Native SSL Hook (Capture Full Traffic)
// ============================================================================
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
        var max = Math.min(len, 32768); 
        for(var i=0; i<max; i++) {
            var c = u8[i];
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

                    var prefix = "[SSL Outgoing]";
                    if (contextMap[sslPtr]) {
                        if (contextMap[sslPtr].fullUrl) prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].fullUrl + "]";
                        else prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].path + "]";
                    }

                    if (methodMatch) {
                        console.log("\n🚀 " + prefix + " Request Headers/Body:\n" + str);
                    } else {
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

                    if (str.startsWith("HTTP/1.1") || str.startsWith("HTTP/2")) {
                        console.log("\n⬅️ " + prefix + " Response Headers:\n" + str);
                    } else {
                        if (str.replace(/\./g, "").trim().length > 0) {
                             console.log("\n⬇️ " + prefix + " Response Body Chunk:\n" + str);
                        }
                    }
                }
            }
        });
    }
    
    console.log("[+] 🛡️ Native SSL Monitoring Active");
}, 1000);

// ============================================================================
// 📦 4. Universal Response Decompression (GZIP + Inflater)
// ============================================================================
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
                                    if (s.length > 2 && (s.includes('"') || s.includes(':') || s.includes('{') || s.includes('['))) {
                                         console.log("\n📦 [DECOMPRESSED] (" + className + ", " + len + "b):\n" + s);
                                    }
                                }
                            } catch(e) {}
                        }
                        return ret;
                    }
                }
            } catch(e) { }
        }

        hookDecompressor("java.util.zip.GZIPInputStream", "read");
        hookDecompressor("java.util.zip.InflaterInputStream", "read");
        
        try {
            var Inflater = Java.use("java.util.zip.Inflater");
            Inflater.inflate.overload('[B', 'int', 'int').implementation = function(b, off, len) {
                var ret = this.inflate(b, off, len);
                if (ret > 0) {
                    try {
                        var StringClass = Java.use("java.lang.String");
                        var s = StringClass.$new(b, off, ret, Java.use("java.nio.charset.Charset").forName("UTF-8")).toString();
                        if (s.length > 2 && (s.includes('"') || s.includes(':') || s.includes('{'))) {
                             console.log("\n📦 [DECOMPRESSED] (Inflater, " + ret + "b):\n" + s);
                        }
                    } catch(e) {}
                }
                return ret;
            }
        } catch(e) {}

        console.log("[+] 📦 Universal Response Logger Active");
    } catch(e) { 
        console.log("[-] Universal Hook Error: " + e); 
    }
});
