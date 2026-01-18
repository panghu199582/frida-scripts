
// Script to scan libalib.so for OpenSSL indicators and traces of static linking
Java.perform(function() {
    console.log("[*] Scanning libalib.so for OpenSSL signatures...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    // 1. BYPASS (Keep this to prevent crash)
    var libAlib = null;
    function isLibAlib(addr) {
        if (!libAlib) libAlib = Process.findModuleByName("libalib.so");
        if (libAlib) {
            var ptrVal = parseInt(addr);
            var base = parseInt(libAlib.base);
            return (ptrVal >= base && ptrVal < base + libAlib.size);
        }
        return false;
    }
    var pthread_create_ptr = Module.findExportByName(null, "pthread_create");
    if (pthread_create_ptr) {
        Interceptor.replace(pthread_create_ptr, new NativeCallback(function(thread_ptr, attr, start_routine, arg) {
            if (isLibAlib(start_routine)) return 0;
            var original = new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            return original(thread_ptr, attr, start_routine, arg);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    }

    // 2. SCAN
    setTimeout(function() {
        var m = Process.findModuleByName("libalib.so");
        if (!m) {
            console.log("[-] libalib.so not found");
            return;
        }

        console.log("[+] Found libalib.so at " + m.base + " (size: " + m.size + ")");

        // Helper to convert string to hex pattern
        function stringToHex(str) {
            var hex = "";
            for (var i = 0; i < str.length; i++) {
                var h = str.charCodeAt(i).toString(16);
                if (h.length < 2) h = "0" + h;
                hex += h + " ";
            }
            return hex.trim();
        }

        // Scan for strings commonly found in OpenSSL
        var strategies = [
            "OpenSSL", 
            "AES_encrypt", 
            "SSL_connect", 
            "SSL_do_handshake", 
            "TLSv1.2",
            "Content-Type",
            "application/json"
        ];

        // Scan for strings commonly found in OpenSSL
        var strategies = [
            "OpenSSL", 
            "AES_encrypt", 
            "SSL_connect", 
            "SSL_do_handshake", 
            "TLSv1.2",
            "Content-Type",
            "application/json",
            "http/1.1"
        ];
        
        // Scan ONLY readable ranges to avoid access violations
        var ranges = m.enumerateRanges('r--');

        strategies.forEach(function(str) {
            var pattern = stringToHex(str);
            
            ranges.forEach(function(range) {
                try {
                    var results = Memory.scanSync(range.base, range.size, pattern);
                    if (results.length > 0) {
                        console.log("  ✅ Found string '" + str + "' at offset " + (results[0].address.sub(m.base)));
                    }
                } catch(e) {
                    // console.log("  [-] Scan error in range: " + e.message);
                }
            });
        });
        
        // Hook all network output to see if we catch the encrypted traffic
        var funcs = ["send", "sendto", "write", "writev"];
        funcs.forEach(function(f) {
            var ptr = Module.findExportByName("libc.so", f);
            if (ptr) {
                Interceptor.attach(ptr, {
                    onEnter: function(args) {
                        if (isLibAlib(this.returnAddress)) {
                             // This confirms libalib is sending data directly
                             console.log("  🚀 [libalib] called " + f);
                        }
                    }
                });
            }
        });

    }, 1000);
});
