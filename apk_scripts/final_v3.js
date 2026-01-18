/*
 * Final V3 - The "Nuclear Option"
 * 1. Java Downgrade: Force HTTP/1.1 in Address (o.a)
 * 2. SSL Unpinning: Set HostnameVerifier & CertificatePinner to NULL/Safe directly in Address
 * 3. Logging: Requests (Native) and Responses (Java GZIP)
 */

if (!Module.findExportByName) {
    Module.findExportByName = function (moduleName, exportName) {
        if (moduleName === null) return Module.findGlobalExportByName(exportName);
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(exportName) : null;
    };
}

Java.perform(function() {
    console.log("[*] 🛡️ [JAVA LAYER] Initializing...");

    try {
        var TargetClass = Java.use("o.a");
        var Arrays = Java.use("java.util.Arrays");
        var List = Java.use("java.util.List");
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");

        // Create a Safe HostnameVerifier
        var SafeVerifier = Java.registerClass({
            name: 'com.example.SafeVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    // console.log("[+] SafeVerifier: Trusting " + hostname);
                    return true;
                }
            }
        });

        // Hook Constructor
        var overloads = TargetClass.$init.overloads;
        overloads.forEach(function(ctor) {
            ctor.implementation = function() {
                var args = arguments;
                var newArgs = [].slice.call(args); 

                // --- 1. Modify Protocols (Index 9) ---
                var PROTO_INDEX = 9;
                if (newArgs.length > PROTO_INDEX && newArgs[PROTO_INDEX]) {
                    var list = Java.cast(newArgs[PROTO_INDEX], List);
                    try {
                        if (list.size() > 0) {
                            var http11 = null;
                            var protoEnum0 = list.get(0);
                            var EnumClass = protoEnum0.getClass();
                            var methodValues = EnumClass.getMethod("values", []);
                            var values = methodValues.invoke(null, []);
                            for(var k=0; k<values.length; k++) {
                                var v = values[k];
                                if (v.toString() == "http/1.1" || v.toString() == "HTTP_1_1") {
                                    http11 = v;
                                    break;
                                }
                            }
                            if (http11) {
                                // console.log("[+] [Java] Forcing HTTP/1.1!");
                                newArgs[PROTO_INDEX] = Arrays.asList([http11]);
                            }
                        }
                    } catch(e) {}
                }

                // --- 2. Remove Certificate Pinner (Index 6: o.g) ---
                // CRASH FIX: Setting this to NULL causes crash in o.k0.h.f.p
                // We will disable pinning separately or rely on TrustManager bypass.
                /*
                var PINNER_INDEX = 6;
                if (newArgs.length > PINNER_INDEX) {
                    newArgs[PINNER_INDEX] = null; 
                }
                */

                // --- 3. Bypass Hostname Verifier (Index 5: HostnameVerifier) ---
                var HV_INDEX = 5;
                if (newArgs.length > HV_INDEX) {
                     // console.log("[+] [Java] Injecting Safe HostnameVerifier!");
                     newArgs[HV_INDEX] = SafeVerifier.$new();
                }

                return this.$init.apply(this, newArgs);
            }
        });
        console.log("[+] [Java] Hooked o.a Constructor (Downgrade + Unpinning Active)");

    } catch(e) {
        // console.log("[-] [Java] Hook Failed: " + e);
    }

    // --- Response Logging (GZIP) ---
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
    console.log("[*] 💉 [NATIVE LAYER] Initializing Request Logger...");

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
        
        var ssl_write = Module.findExportByName(lib, "SSL_write");
        if (ssl_write) {
            Interceptor.attach(ssl_write, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0) {
                        var str = safeStr(args[1], len);
                        if (str.match(/^(GET|POST|PUT|DELETE|HEAD) \//)) {
                             console.log("\n🚀 [REQUEST HEADERS] ("+lib+"):\n" + str);
                        } else if (str.includes("Authorization") || str.includes("Bearer")) {
                             console.log("\n🔑 [TOKEN] ("+lib+"):\n" + str);
                        } else if (str.startsWith("PRI * HTTP/2")) {
                             console.log("\n⚠️ [H2] ("+lib+") - Downgrade missed?");
                        } else if (str.includes("requestHeader") || str.includes("devicePubKey")) {
                            console.log("\n📦 [REQUEST BODY] ("+lib+"):\n" + str);
                        }
                    }
                }
            });
        }
        // Native Unpinning (Backup)
        var set_verify = Module.findExportByName(lib, "SSL_set_verify");
        if (set_verify) Interceptor.attach(set_verify, { onEnter: function(a){ a[1]=ptr(0); a[2]=ptr(0); }});
        var get_result = Module.findExportByName(lib, "SSL_get_verify_result");
        if (get_result) Interceptor.attach(get_result, { onLeave: function(r){ r.replace(0); }});
    });
}, 0);
