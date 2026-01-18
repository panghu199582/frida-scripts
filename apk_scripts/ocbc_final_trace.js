/*
 * OCBC Final Tracer V2: Aggressive Localhost & SSL Capture
 */

Java.perform(function() {
    console.log("[*] 🛡️ OCBC Tracer V2 Active");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    // ====================================================================
    // 1. ANT-DETECTION BYPASS (Required)
    // ====================================================================
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
            if (isLibAlib(start_routine)) return 0; // Block libalib threads
            return new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer'])(thread_ptr, attr, start_routine, arg);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    }

    // ====================================================================
    // 2. UNIVERSAL SOCKET TRACING (Focus on 127.0.0.1)
    // ====================================================================
    var monitoredFDs = new Set();
    
    function hexDump(buf, len) {
        var u8 = new Uint8Array(buf.readByteArray(Math.min(len, 2048)));
        var hex = [];
        var ascii = "";
        for(var i=0; i<Math.min(len, 32); i++) {
            var z = u8[i].toString(16);
            if (z.length < 2) z = "0"+z;
            hex.push(z);
        }
        for(var i=0; i<Math.min(len, 64); i++) {
            var c = u8[i];
            if (c >= 32 && c <= 126) ascii += String.fromCharCode(c);
            else ascii += ".";
        }
        return "   HEX: " + hex.join(" ") + "... \n   ASC: " + ascii;
    }

    var connectPtr = Module.findExportByName("libc.so", "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.addr = args[1];
                
                var family = this.addr.readU16();
                if (family === 2) { // AF_INET
                    var port = ((this.addr.add(2).readU16() & 0xFF) << 8) | ((this.addr.add(2).readU16() >> 8) & 0xFF);
                    var ip = [];
                    for(var i=0;i<4;i++) ip.push(this.addr.add(4+i).readU8());
                    var ipStr = ip.join(".");

                    // Capture ALL localhost connections or connections from libalib
                    if (ipStr.startsWith("127.") || isLibAlib(this.returnAddress)) {
                        console.log("\n🚩 [Socket] CONNECT FD=" + this.fd + " -> " + ipStr + ":" + port);
                        monitoredFDs.add(this.fd);
                    }
                }
            }
        });
    }

    // Hook Write/Send
    var funcs = ["write", "send", "sendto"];
    funcs.forEach(function(f) {
        var ptr = Module.findExportByName("libc.so", f);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    var fd = args[0].toInt32();
                    if (monitoredFDs.has(fd)) {
                        var len = args[2].toInt32();
                        if (len > 0) {
                            console.log("\n⬆️ [Socket] SEND (FD=" + fd + ", " + len + "b)");
                            console.log(hexDump(args[1], len));
                        }
                    }
                }
            });
        }
    });

    // Hook Read/Recv
    var funcsIn = ["read", "recv", "recvfrom"];
    funcsIn.forEach(function(f) {
        var ptr = Module.findExportByName("libc.so", f);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && monitoredFDs.has(this.fd)) {
                        console.log("\n⬇️ [Socket] RECV (FD=" + this.fd + ", " + len + "b)");
                        console.log(hexDump(this.buf, len));
                    }
                }
            });
        }
    });

    // ====================================================================
    // 3. SYSTEM SSL MONITOR (To catch the final egress)
    // ====================================================================
    setTimeout(function() {
        var modules = Process.enumerateModules();
        var sslLibs = modules.filter(m => m.name.includes("libssl") || m.name.includes("conscrypt"));
        
        sslLibs.forEach(function(m) {
            var write = Module.findExportByName(m.name, "SSL_write");
            if (write) {
                Interceptor.attach(write, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            var buf = args[1].readByteArray(Math.min(len, 1024));
                            var str = "";
                            var u8 = new Uint8Array(buf);
                            for(var i=0; i<u8.length; i++) {
                                var c = u8[i];
                                if((c>=32&&c<=126)||c==10||c==13) str+=String.fromCharCode(c);
                                else str+=".";
                            }
                            if (str.includes("HTTP/") || str.includes("POST") || str.includes("GET") || str.includes("{")) {
                                console.log("\n� [" + m.name + "] SSL_write:\n" + str.substring(0, 500));
                            }
                        } catch(e) {}
                    }
                });
            }
        });
    }, 2000);

});
