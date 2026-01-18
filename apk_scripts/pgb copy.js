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

    // Helper: Deep Inspect Java Objects (Reflection)
    function inspectObject(obj, depth) {
        if (depth === undefined) depth = 0;
        if (depth > 5) return "..."; 
        if (obj === null || obj === undefined) return "null";
        
        try {
            var javaObj = Java.cast(obj, ObjectClass);
            var cls = javaObj.getClass();
            var clsName = cls.getName();
            var str = "[" + clsName + "]@" + javaObj.hashCode().toString(16);

           // 1. Inspect Proxy InvocationHandler
            if (ProxyClass.isProxyClass(cls)) {
                try {
                    var handler = ProxyClass.getInvocationHandler(javaObj);
                    str += "\n" + "  ".repeat(depth) + "Handler: " + inspectObject(handler, depth + 1);
                } catch(e) { str += " [Handler Error: " + e + "]"; }
            }

            // 2. Inspect Fields for certain classes (App, Retrofit, OkHttp 'o.')
            if (clsName.indexOf("f.l.a") !== -1 || clsName.indexOf("pgbank") !== -1 || clsName.indexOf("r.") !== -1 || clsName.indexOf("retrofit") !== -1 || clsName.indexOf("Proxy") !== -1 || clsName.indexOf("o.") !== -1) {
                str += "\n" + "  ".repeat(depth) + "Fields {";
                var fields = cls.getDeclaredFields();
                for (var i = 0; i < fields.length; i++) {
                    try {
                        fields[i].setAccessible(true);
                        var val = fields[i].get(javaObj);
                        var valStr = "null";
                        
                        if (val !== null) {
                            var fieldClsName = val.getClass().getName();
                            
                            // Always show Strings
                            if (fieldClsName.indexOf("String") !== -1) {
                                valStr = val.toString();
                            } 
                            // Recurse into interesting objects (like r.s, o.w, o.a0)
                            else if (fieldClsName.indexOf("r.") !== -1 || fieldClsName.indexOf("o.") !== -1 || fieldClsName.indexOf("Proxy") !== -1) {
                                valStr = inspectObject(val, depth + 1); // Recurse
                            }
                            else if (fieldClsName.startsWith("[L")) {
                                valStr = "[Array " + fieldClsName + "]";
                            }
                            // Show primitives
                            else if (fieldClsName.indexOf("Integer") !== -1 || fieldClsName.indexOf("Boolean") !== -1) {
                                valStr = val.toString();
                            }
                            else {
                                valStr = "[" + fieldClsName + "]";
                            }
                        }
                        str += "\n" + "  ".repeat(depth+1) + fields[i].getName() + ": " + valStr;
                    } catch(e) { }
                }
                str += "\n" + "  ".repeat(depth) + "}";
            }
            return str;
        } catch(e) { return "[Inspect Error]: " + e; }
    }

    console.log("[*] Installing Java Hooks...");

    // 1. Trace App Network Handler (f.l.a.h.d.h)
    try {
        var HClass = Java.use("f.l.a.h.d.h");
        var methods = HClass.class.getDeclaredMethods();
        methods.forEach(function(m) {
            var name = m.getName();
            if (["b", "n", "a"].includes(name)) { 
                var overloads = HClass[name].overloads;
                overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        console.log("\n[AppLogic] f.l.a.h.d.h." + name + "() called");
                        if (this.$className) {
                             // Keep inspection to see changes
                             console.log("  [Context 'this']:\n" + inspectObject(this, 0));
                        }
                        return this[name].apply(this, arguments);
                    }
                });
            }
        });
        console.log("[+] Hooked f.l.a.h.d.h");
    } catch(e) { console.log("[-] f.l.a.h.d.h Hook Error: " + e); }

    // 2. Hook Config Class f.l.a.j.a directly
    try {
        var ConfigClass = Java.use("f.l.a.j.a");
        var methods = ConfigClass.class.getDeclaredMethods();
        methods.forEach(function(m) {
            if ((m.getName().startsWith("get") || m.getName().length < 3) && m.getReturnType().getName() === "java.lang.String") {
                var overloads = ConfigClass[m.getName()].overloads;
                overloads.forEach(function(ov) {
                     ov.implementation = function() {
                         var ret = this[m.getName()].apply(this, arguments);
                         console.log("  [Config] f.l.a.j.a." + m.getName() + "() -> " + ret);
                         return ret;
                     }
                });
            }
        });
        console.log("[+] Hooked f.l.a.j.a (Config)");
    } catch(e) { }

    // ... (Keep existing helpers)

    // 3. Hook Obfuscated OkHttp Classes
    
    // A. HttpUrl (o.w) - Reduce Noise
    try {
        var HttpUrl = Java.use("o.w");
        HttpUrl.toString.implementation = function() {
            var ret = this.toString();
            // console.log("\n[OkHttp URL] " + ret); // Optional: keep enabled if you want per-access logs
            return ret;
        }
        console.log("[+] Hooked o.w (HttpUrl) - Silent Mode");
    } catch(e) { console.log("[-] o.w Hook Error: " + e); }

    // B. OkHttpClient (o.a0) -> Capture Request!
    // We look for 'newCall(Request)' equivalent.
    // It's likely a method taking 1 arg and returning a Call (interface).
    try {
        var Client = Java.use("o.a0");
        var clientMethods = Client.class.getDeclaredMethods();
        
        clientMethods.forEach(function(m) {
            var params = m.getParameterTypes();
            // newCall(Request) -> Call
            if (params.length === 1) {
                 var overloads = Client[m.getName()].overloads;
                 overloads.forEach(function(ov) {
                    ov.implementation = function(req) {
                        // This 'req' is likely the Request object!
                        // request.toString() is usually very descriptive in OkHttp: "Request{method=POST, url=..., tags=...}"
                        var reqInfo = "";
                        try {
                            reqInfo = req.toString();
                        } catch(e) { reqInfo = "[Req Null]"; }
                        
                        console.log("\n[OkHttp Request] " + m.getName() + "(): " + reqInfo);

                        // If toString() is obfuscated/useless, deep inspect the Request object
                        if (reqInfo.indexOf("Request") === -1 && reqInfo.indexOf("http") === -1) {
                             console.log("  [Request Dump]:\n" + inspectObject(req, 0));
                        } else {
                            // Try to find Headers in the request object (likely a field of type o.r)
                            // We can use inspectObject to find fields of type o.r inside 'req'
                            // But inspectObject is recursive, so it might output it above.
                        }
                        
                        return this[m.getName()](req);
                    }
                });
            }
        });
        console.log("[+] Hooked o.a0 (OkHttpClient)");
    } catch(e) { console.log("[-] o.a0 Hook Error: " + e); }

    // C. Headers (o.r) - Just hook toString for validation
    try {
        var Headers = Java.use("o.r");
        Headers.toString.implementation = function() {
            var ret = this.toString();
            // Headers.toString() usually prints all headers
            // console.log("  [Headers.toString] " + ret); 
            return ret;
        }
    } catch(e) {}

    // 4. Response Decompression (Decoder)
    // ... (Keep existing decoder logic)



    // 4. Response Decompression (Decoder)
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
                                const snippet = ptr.readByteArray(Math.min(len, 4));
                                const u8 = new Uint8Array(snippet);
                                if (!(u8[0] === 0x1f && u8[1] === 0x8b)) {
                                     const str = ptr.readUtf8String(Math.min(len, 32768));
                                     if (str && (str.startsWith("POST") || str.startsWith("GET") || str.startsWith("PUT"))) {
                                         console.log(`\n⬆️ [Req Headers] (${libName}) >>>\n${str}`);
                                     }
                                }
                            } catch(e) {}
                        }
                    }
                });
            }
        }
    });
}

setTimeout(hookSSL, 1000);