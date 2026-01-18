
/*
 * 🌐 Universal Network Capture Script (Stability Focused)
 * 
 * Features:
 * 1. [High-Level] OkHttp3 Logging (Request/Response Headers & URLs)
 * 2. [Low-Level] Native SSL Hooking (Supports standard SSL, BoringSSL, Conscrypt)
 * 3. [Fallback] Java Socket Logging (Raw TCP Streams)
 * 
 * Usage: frida -U -f com.example.package -l this_script.js
 */

Java.perform(function() {
    console.log("======================================================");
    console.log("[*] 🚀 Universal Network Capture Started");
    console.log("======================================================");

    // ====================================================================
    // [PART 1] OKHTTP3 HIGH-LEVEL LOGGING
    // ====================================================================
    try {
        var RealCall = Java.use("okhttp3.RealCall");
        
        // Log Synchronous Requests
        RealCall.execute.overload().implementation = function() {
            try {
                var req = this.request();
                console.log("\n📦 [OkHttp3-Sync] " + req.method() + " " + req.url());
                // Optional: headers
                // console.log("   " + req.headers().toString());
            } catch(e) {}
            return this.execute();
        };

        // Log Asynchronous Requests
        RealCall.enqueue.overload('okhttp3.Callback').implementation = function(cb) {
            try {
                var req = this.request();
                console.log("\n📦 [OkHttp3-Async] " + req.method() + " " + req.url());
            } catch(e) {}
            return this.enqueue(cb);
        };
        console.log("[+] OkHttp3 Hooks Active");
    } catch(e) {
        console.log("[-] OkHttp3 not found or obfuscated. Using fallback...");
    }

    // ====================================================================
    // [PART 2] JAVA SOCKET RAW LOGGING (HttpUrlConnection / Obfuscated)
    // ====================================================================
    try {
        var SocketOutputStream = Java.use("java.net.SocketOutputStream");
        
        function logSocketOutput(buffer, offset, length) {
            try {
                var sub = Java.array('byte', buffer).slice(offset, offset + length);
                var str = "";
                for(var i=0; i<Math.min(sub.length, 1024); i++) {
                    var c = sub[i];
                    if ((c >= 32 && c <= 126) || c === 10 || c === 13) str += String.fromCharCode(c);
                    else str += ".";
                }
                
                // Filter: Only generic HTTP methods
                if (str.match(/^(GET|POST|PUT|DELETE|HEAD|CONNECT|OPTIONS|PATCH) /)) {
                    console.log("\n🔌 [JavaSocket-Out] \n" + str.substring(0, 1000));
                }
            } catch(e) {}
        }

        SocketOutputStream.socketWrite0.overload('java.io.FileDescriptor', '[B', 'int', 'int').implementation = function(fd, b, off, len) {
            logSocketOutput(b, off, len);
            return this.socketWrite0(fd, b, off, len);
        }
        console.log("[+] Java Socket Hooks Active");
    } catch(e) { 
        console.log("[-] Java Socket Hooks skipped: " + e.message);
    }

    // ====================================================================
    // [PART 3] NATIVE SSL LOGGER (ConsCrypt / OpenSSL / BoringSSL)
    // ====================================================================
    // Delayed start to ensure libraries are loaded
    setTimeout(function() {
        console.log("[*] Scanning for Native SSL Libraries...");
        
        var modules = Process.enumerateModules();
        var sslFuncs = [];
        
        // Common library names to hook
        var targetLibs = ["libssl.so", "libboringssl.so", "libconscrypt.so", "libmonochrome.so", "libcrypto.so"];

        // 1. Find imported functions first (System SSL)
        targetLibs.forEach(function(libName) {
            var m = Process.findModuleByName(libName);
            if (m) {
                console.log("    -> Found " + libName);
                var ssl_write = Module.findExportByName(libName, "SSL_write");
                var ssl_read = Module.findExportByName(libName, "SSL_read");
                
                if (ssl_write) attachNativeHook(libName, "SSL_write", ssl_write, false);
                if (ssl_read) attachNativeHook(libName, "SSL_read", ssl_read, true);
            }
        });

    }, 2000);

    function attachNativeHook(libName, funcName, address, isRead) {
        Interceptor.attach(address, {
            onEnter: function(args) {
                if (!isRead) { // SSL_write: log input (args[1])
                    var len = args[2].toInt32();
                    if (len > 0) {
                        try {
                            var buf = args[1].readByteArray(Math.min(len, 4096));
                            prettyLogNative(libName, funcName, buf, len);
                        } catch(e) {}
                    }
                } else { // SSL_read: store buf ptr
                    this.buf = args[1];
                }
            },
            onLeave: function(retval) {
                if (isRead && this.buf) { // SSL_read: log output (buf)
                    var retLen = retval.toInt32();
                    if (retLen > 0) {
                        try {
                            var buf = this.buf.readByteArray(Math.min(retLen, 4096));
                            prettyLogNative(libName, funcName, buf, retLen);
                        } catch(e) {}
                    }
                }
            }
        });
    }

    function prettyLogNative(lib, func, buffer, len) {
        var u8 = new Uint8Array(buffer);
        var str = "";
        var hasText = false;
        
        // Check text content
        for(var i=0; i<u8.length; i++) {
            var c = u8[i];
            if((c >= 32 && c <= 126) || c == 10 || c == 13) {
                str += String.fromCharCode(c);
            } else {
                str += ".";
            }
        }
        
        // Smart Filter: Only log if we see HTTP-like keywords to reduce noise
        // Capture: GET, POST, HTTP, { (JSON), < (XML)
        if (str.match(/^(GET|POST|PUT|DELETE|HTTP\/|Host:)/) || (str.includes('"{') || str.includes('{"'))) {
            var prefix = (func === "SSL_write") ? "⬆️" : "⬇️";
            console.log("\n" + prefix + " [" + lib + "::" + func + "] (" + len + "b):\n" + str.substring(0, 1500));
        }
    }

});
