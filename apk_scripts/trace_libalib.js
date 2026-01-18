
// Combined script: Bypass + Analyze libalib.so

Java.perform(function() {
    // ====================================================================
    // 1. BYPASS (Essential to keep app alive)
    // ====================================================================
    console.log("[*] Anti-Detection: Blocking libalib.so threads...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    var libAlib = null;
    function isLibAlib(addr) {
        if (!libAlib) libAlib = Process.findModuleByName("libalib.so");
        if (libAlib) {
            var ptrVal = parseInt(addr);
            var base = parseInt(libAlib.base);
            var end = base + libAlib.size;
            return (ptrVal >= base && ptrVal < end);
        }
        return false;
    }

    var pthread_create_ptr = Module.findExportByName(null, "pthread_create");
    if (pthread_create_ptr) {
        Interceptor.replace(pthread_create_ptr, new NativeCallback(function(thread_ptr, attr, start_routine, arg) {
            if (isLibAlib(start_routine)) {
                // console.log("[!] BLOCKED thread creation from libalib.so! Entry: " + start_routine);
                return 0; // Success (fake)
            }
            var original = new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            return original(thread_ptr, attr, start_routine, arg);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    }

    // ====================================================================
    // 2. ANALYZE LIBALIB IMPORTS & NETWORKING
    // ====================================================================
    // We want to see if libalib calls standard send/recv or SSL functions
    
    setTimeout(function() {
        var alib = Process.findModuleByName("libalib.so");
        if (alib) {
            console.log("==========================================");
            console.log("Analyzing libalib.so (" + alib.base + ")...");
            console.log("==========================================");

            // 1. Check Imports - does it use system SSL?
            var imports = alib.enumerateImports();
            var usesSSL = false;
            imports.forEach(function(imp) {
                if (imp.name.indexOf("SSL_") >= 0 || imp.name.indexOf("crypto") >= 0) {
                     console.log("  Imported: " + imp.name + " from " + imp.module);
                     usesSSL = true;
                }
            });
            if (!usesSSL) console.log("  [*] No obvious SSL imports found. Likely uses static OpenSSL or custom crypto.");


            // 2. Hook connect/send/write SPECIFICALLY for calls originating from libalib
            
            var connectPtr = Module.findExportByName("libc.so", "connect");
            Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    if (isLibAlib(this.returnAddress)) {
                         this.isAlib = true;
                         this.fd = args[0].toInt32();
                         var sockAddr = args[1];
                         var port = ((sockAddr.add(2).readU16() & 0xFF) << 8) | ((sockAddr.add(2).readU16() >> 8) & 0xFF);
                         
                         // Hacky IP read
                         var ip = [];
                         for(var i=0;i<4;i++) ip.push(sockAddr.add(4+i).readU8());
                         this.dest = ip.join(".") + ":" + port;
                         
                         console.log("\n🚩 [libalib] Connecting raw socket (FD=" + this.fd + ") -> " + this.dest);
                    }
                }
            });

            var sendPtr = Module.findExportByName("libc.so", "send");
            var writePtr = Module.findExportByName("libc.so", "write"); 
            
            function traceWrite(name, fd, buf, len, lr) {
                if (isLibAlib(lr)) {
                    if (len > 0) {
                        console.log("\n🚩 [libalib] " + name + "(FD=" + fd + ", len=" + len + ")");
                        // Dump hex/string
                        // Check if it looks like SSL (0x16 0x03...) or HTTP
                        var data = buf.readByteArray(Math.min(len, 256));
                        console.log(hexdump(data, { offset: 0, length: Math.min(len, 64), header: false, ansi: false }));
                    }
                }
            }

            Interceptor.attach(sendPtr, {
                onEnter: function(args) {
                    traceWrite("send", args[0].toInt32(), args[1], args[2].toInt32(), this.returnAddress);
                }
            });
            Interceptor.attach(writePtr, {
                onEnter: function(args) {
                    traceWrite("write", args[0].toInt32(), args[1], args[2].toInt32(), this.returnAddress);
                }
            });

        } else {
            console.log("[-] libalib.so not found yet.");
        }
    }, 2000);
});
