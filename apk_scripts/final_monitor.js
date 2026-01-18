/*
 * Final Bank Monitor (Hybrid Force-H1 Edition)
 * Compatible with Frida 17.5.2+
 *
 * Strategies used:
 * 1. Java-side OkHttp/Cronet Re-configuration -> Forces HTTP/1.1 (Best for stability)
 * 2. Native-side ALPN Hook -> Forces HTTP/1.1 (Best for native/obfuscated SSL)
 * 3. Java-side GZIP Hook -> Captures plain-text Response Body
 * 4. Native-side SSL_write -> Captures Request Headers/Body
 */

// ================= PLUGINS =================
// Frida 17+ Compatibility Polyfill for Module.findExportByName
if (!Module.findExportByName) {
    Module.findExportByName = function (moduleName, exportName) {
        if (moduleName === null) return Module.findGlobalExportByName(exportName);
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(exportName) : null;
    };
}
// ===========================================

Java.perform(function() {
    console.log("[*] 🛡️ [JAVA LAYER] Initializing...");

    // 1. FORCE HTTP/1.1 (Java - OkHttp)
    // Most likely to succeed if app uses OkHttp
    try {
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        var Protocol = Java.use("okhttp3.Protocol");
        var Arrays = Java.use("java.util.Arrays");
        
        // Hook protocols() method
        OkHttpClientBuilder.protocols.implementation = function(protocols) {
            // console.log("[+] [Java] OkHttp: Forcing HTTP/1.1");
            return this.protocols(Arrays.asList([Protocol.HTTP_1_1.value]));
        };
        console.log("[+] [Java] Hooked OkHttpClient$Builder to force HTTP/1.1");
    } catch(e) {
        // console.log("[-] OkHttp hooks failed (Obfuscated?): " + e);
    }

    // 2. FORCE HTTP/1.1 (Java - Cronet)
    try {
        var CronetBuilder = Java.use("org.chromium.net.CronetEngine$Builder");
        CronetBuilder.enableHttp2.implementation = function(enable) {
            // console.log("[+] [Java] Cronet: Disabling HTTP/2");
            return this.enableHttp2(false);
        };
        CronetBuilder.enableQuic.implementation = function(enable) {
            // console.log("[+] [Java] Cronet: Disabling QUIC");
            return this.enableQuic(false);
        };
        console.log("[+] [Java] Hooked CronetEngine$Builder to force HTTP/1.1");
    } catch(e) {}

    // 3. RESPONSE BODY CAPTURE (GZIP)
    // The "H2 Detector" reported body is compressed/binary. This solves the Response part.
    try {
        var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
        var StringClass = Java.use("java.lang.String");
        var Charset = Java.use("java.nio.charset.Charset");
        var utf8 = Charset.forName("UTF-8");

        GZIPInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
            var ret = this.read(buffer, offset, length);
            if (ret > 0) {
                try {
                    // Convert byte[] to String to see JSON
                    var s = StringClass.$new(buffer, offset, ret, utf8).toString();
                    if (s.trim().startsWith("{") || s.trim().startsWith("[")) {
                        console.log("\n⬇️ [RESPONSE - GZIP DECODED]:\n" + s);
                    }
                } catch(e) {}
            }
            return ret;
        }
        console.log("[+] [Java] Hooked GZIPInputStream for transparent response decoding");
    } catch(e) {}
});




// RUN NATIVE HOOKS IMMEDIATELY (No Timeout)
// This prevents race conditions where the first connection happens before we hook.
(function() {
    console.log("[*] 💉 [NATIVE LAYER] Initializing immediately...");

    // Helper: Safe String for Frida 17+
    function safeStr(buf, len) {
        // Read buffer safely
        var buffer = buf.readByteArray(len);
        if (!buffer) return "";
        var u8 = new Uint8Array(buffer);
        var s = "";
        // Read first 2KB max
        for(var i=0; i<Math.min(len, 2048); i++) {
            var c = u8[i];
            // Filter non-printable
            if ((c>=32 && c<=126) || c==10 || c==13) s += String.fromCharCode(c);
            else s += ".";
        }
        return s;
    }

    // Force HTTP/1.1 via ALPN (Native)
    function hookALPN(libName) {
        var f1 = Module.findExportByName(libName, "SSL_CTX_set_alpn_protos");
        var f2 = Module.findExportByName(libName, "SSL_set_alpn_protos");
        
        var callback = {
            onEnter: function(args) {
                try {
                    var protos = args[1]; // const unsigned char *protos
                    var len = args[2].toInt32(); // unsigned int protos_len
                    
                    var newProtos = [];
                    var p = 0;
                    var modified = false;

                    // Parse the specific ALPN wire format: [Len][Bytes][Len][Bytes]
                    while (p < len) {
                        var l = protos.add(p).readU8();
                        var protocolProto = protos.add(p + 1);
                        var protocol = protocolProto.readUtf8String(l);
                        
                        if (protocol === 'h2') {
                            modified = true;
                        } else {
                            newProtos.push(l);
                            for (var i = 0; i < l; i++) newProtos.push(protos.add(p + 1 + i).readU8());
                        }
                        p += 1 + l;
                    }

                    if (modified) {
                        console.log("[!] [ALPN] " + libName + ": Removing 'h2' capability to force plaintext headers.");
                        
                        // Alloc new buffer
                        var newPtr = Memory.alloc(newProtos.length);
                        newPtr.writeByteArray(newProtos);
                        
                        // Replace arguments
                        // args[1] = newPtr; // <--- DISABLED to fix Freeze/Crash
                        // args[2] = new NativePointer(newProtos.length);
                        console.log("    (Modifications disabled to prevent app freeze)");
                    }
                } catch(e) {
                    console.log("[-] ALPN Hook Error in " + libName + ": " + e);
                }
            }
        };

        if (f1) Interceptor.attach(f1, callback);
        if (f2) Interceptor.attach(f2, callback);
    }

    var libs = ["libssl.so", "libboringssl.so", "libcronet.so", "stable_cronet_libssl.so", "libconscrypt_jni.so"];

    libs.forEach(function(lib) {
        var mod = Process.findModuleByName(lib);
        if (!mod) return;
        
        // 1. Hook ALPN (Force H1)
        // hookALPN(lib); // DISABLED: Causing App Freeze

        // 2. SSL Logging
        var ssl_write = Module.findExportByName(lib, "SSL_write");
        if (ssl_write) {
            Interceptor.attach(ssl_write, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0) {
                        var buf = args[1];
                        var str = safeStr(buf, len);
                        
                        // Detection Logic
                        if (str.match(/^(GET|POST|PUT|DELETE|HEAD) \//)) {
                            console.log("\n🚀 [REQUEST HEADERS] ("+lib+"):\n" + str);
                        } else if (str.startsWith("PRI * HTTP/2")) {
                            console.log("\n⚠️ ["+lib+"] Detected HTTP/2 Handshake. (ALPN Hook missed or ignored?)");
                        } else if (str.includes("Authorization") || str.includes("Bearer")) {
                            console.log("\n🔑 [TOKEN FOUND] ("+lib+"): " + str);
                        } else if (str.includes('"{') || str.includes('{"')) {
                             console.log("\n📦 [REQUEST BODY] ("+lib+"):\n" + str);
                        }
                    }
                }
            });
        }
        
        // 3. SSL Pinning Bypass (For Proxy)
        var set_verify = Module.findExportByName(lib, "SSL_set_verify");
        if (set_verify) Interceptor.attach(set_verify, { onEnter: function(a){ a[1]=ptr(0); a[2]=ptr(0); }});

        var get_result = Module.findExportByName(lib, "SSL_get_verify_result");
        if (get_result) Interceptor.attach(get_result, { onLeave: function(r){ r.replace(0); }});
    });
})();
