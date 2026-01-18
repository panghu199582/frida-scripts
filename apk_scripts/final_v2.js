/*
 * Final V2 - The Ultimate Monitor
 * Integrates:
 * 1. Java Downgrade (Target: o.a) -> Forces HTTP/1.1 safetly
 * 2. SSL Unpinning (Java + Native) -> Allows proxying if possible
 * 3. Traffic Logging (Request + Response) -> Captures payload even if proxy fails
 */

// Frida 17+ Polyfill
if (!Module.findExportByName) {
    Module.findExportByName = function (moduleName, exportName) {
        if (moduleName === null) return Module.findGlobalExportByName(exportName);
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(exportName) : null;
    };
}

Java.perform(function() {
    console.log("[*] 🛡️ [JAVA LAYER] Initializing...");

    // ==========================================================
    // 1. JAVA DOWNGRADE (Target: o.a)
    // ==========================================================
    try {
        var TargetClass = Java.use("o.a");
        var Arrays = Java.use("java.util.Arrays");
        var overloads = TargetClass.$init.overloads;
        
        overloads.forEach(function(ctor) {
            ctor.implementation = function() {
                var args = arguments;
                var newArgs = [].slice.call(args); // Convert to JS Array
                var PROTO_INDEX = 9;

                // Check index 9 (protocols)
                if (newArgs.length > PROTO_INDEX) {
                    var list = newArgs[PROTO_INDEX];
                    if (list) {
                        try {
                            if (list.size() > 0) {
                                var protoEnum0 = list.get(0);
                                var EnumClass = protoEnum0.getClass();
                                var methodValues = EnumClass.getMethod("values", []);
                                var values = methodValues.invoke(null, []);
                                
                                var http11 = null;
                                for(var k=0; k<values.length; k++) {
                                    var v = values[k];
                                    if (v.toString() == "http/1.1" || v.toString() == "HTTP_1_1") {
                                        http11 = v;
                                        break;
                                    }
                                }

                                if (http11) {
                                    // console.log("[+] [Java] Forcing HTTP/1.1 in o.a Constructor");
                                    newArgs[PROTO_INDEX] = Arrays.asList([http11]);
                                }
                            }
                        } catch(e) {}
                    }
                }
                return this.$init.apply(this, newArgs);
            }
        });
        console.log("[+] [Java] Hooked o.a Constructor (Downgrade Active)");
    } catch(e) {
        console.log("[-] [Java] o.a Hook Failed: " + e);
    }

    // ==========================================================
    // 2. JAVA SSL UNPINNING (TrustManager & CertPinner)
    // ==========================================================
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var ArrayList = Java.use("java.util.ArrayList");
        TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            // console.log("[+] [Java] TrustManager Bypass");
            return ArrayList.$new();
        }
        // Also Obfuscated CertificatePinner? (o.g ?)
        // Based on JADX: o.g corresponds to CertificatePinner (field 'h' in o.a)
        // Let's verify 'o.g' structure or assume it's standard or unused if we bypass TrustManager.
    } catch(e) {}

    // ==========================================================
    // 3. RESPONSE LOGGER (GZIP)
    // ==========================================================
    try {
        var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
        var StringClass = Java.use("java.lang.String");
        var Charset = Java.use("java.nio.charset.Charset");
        var utf8 = Charset.forName("UTF-8");

        GZIPInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
            var ret = this.read(buffer, offset, length);
            if (ret > 0) {
                try {
                    var s = StringClass.$new(buffer, offset, ret, utf8).toString();
                    if (s.trim().startsWith("{") || s.trim().startsWith("[")) {
                        console.log("\n⬇️ [RESPONSE - GZIP]:\n" + s);
                    }
                } catch(e) {}
            }
            return ret;
        }
        console.log("[+] [Java] Hooked GZIPInputStream");
    } catch(e) {}
});

setTimeout(function() {
    console.log("[*] 💉 [NATIVE LAYER] Initializing...");

    // Helper: Safe String
    function safeStr(buf, len) {
        var buffer = buf.readByteArray(len);
        if(!buffer) return "";
        var u8 = new Uint8Array(buffer);
        var s = "";
        for(var i=0; i<Math.min(len, 2048); i++) {
            var c = u8[i];
            if ((c>=32 && c<=126) || c==10 || c==13) s += String.fromCharCode(c);
            else s += ".";
        }
        return s;
    }

    var libs = ["libssl.so", "libboringssl.so", "libcronet.so", "stable_cronet_libssl.so"];
    
    libs.forEach(function(lib) {
        var mod = Process.findModuleByName(lib);
        if (!mod) return;

        // 1. SSL Unpinning (Native)
        var set_verify = Module.findExportByName(lib, "SSL_set_verify");
        if (set_verify) Interceptor.attach(set_verify, { onEnter: function(a){ a[1]=ptr(0); a[2]=ptr(0); }});
        var get_result = Module.findExportByName(lib, "SSL_get_verify_result");
        if (get_result) Interceptor.attach(get_result, { onLeave: function(r){ r.replace(0); }});

        // 2. Request Logger (Ideally HTTP/1 now)
        var ssl_write = Module.findExportByName(lib, "SSL_write");
        if (ssl_write) {
            Interceptor.attach(ssl_write, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0) {
                        var buf = args[1];
                        var str = safeStr(buf, len);
                        if (str.match(/^(GET|POST|PUT|DELETE|HEAD) \//)) {
                             console.log("\n🚀 [REQUEST HEADERS] ("+lib+"):\n" + str);
                        } else if (str.includes("Authorization") || str.includes("Bearer")) {
                             console.log("\n🔑 [TOKEN] ("+lib+"):\n" + str);
                        } else if (str.startsWith("PRI * HTTP/2")) {
                             console.log("\n⚠️ [H2] ("+lib+") still active! Java Downgrade might have missed.");
                        } else if (str.includes("requestHeader") || str.includes("devicePubKey")) {
                            // JSON Body
                            console.log("\n📦 [REQUEST BODY] ("+lib+"):\n" + str);
                        }
                    }
                }
            });
        }
    });
}, 0); // Immediate
