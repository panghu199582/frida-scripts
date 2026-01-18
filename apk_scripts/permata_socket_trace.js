/*
 * Permata Socket Tracer (Enhanced)
 * Captures Raw Hex DO and attempts SSL Decryption
 */

Java.perform(function() {
    console.log("[*] 🔌 Starting Permata Socket Tracer (Hex + SSL Mode)...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    // Helper: Hex Dump
    function hexDump(arr, off, len) {
        var hex = [];
        var ascii = "";
        for(var i=0; i<Math.min(len, 256); i++) {
            var b = arr[off+i];
            var h = (b & 0xFF).toString(16);
            if (h.length < 2) h = "0"+h;
            hex.push(h);
            if (b >= 32 && b <= 126) ascii += String.fromCharCode(b);
            else ascii += ".";
        }
        return "   HEX: " + hex.join(" ") + (len > 256 ? " ..." : "") + "\n   ASC: " + ascii;
    }

    // ====================================================================
    // 1. JAVA SOCKETS (RAW ENCRYPTED TRAFFIC)
    // ====================================================================
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            console.log("\n☕ [JavaSocket] Connecting to: " + endpoint.toString());
            this.connect(endpoint, timeout);
        }

        var SocketOutputStream = Java.use("java.net.SocketOutputStream");
        SocketOutputStream.socketWrite0.overload('java.io.FileDescriptor', '[B', 'int', 'int').implementation = function(fd, b, off, len) {
            console.log("\n⬆️ [JavaSocket-Out] (" + len + "b)");
            console.log(hexDump(b, off, len));
            this.socketWrite0(fd, b, off, len);
        }

        var SocketInputStream = Java.use("java.net.SocketInputStream");
        SocketInputStream.socketRead0.overload('java.io.FileDescriptor', '[B', 'int', 'int', 'int').implementation = function(fd, b, off, len, timeout) {
            var ret = this.socketRead0(fd, b, off, len, timeout);
            if (ret > 0) {
                console.log("\n⬇️ [JavaSocket-In] (" + ret + "b)");
                console.log(hexDump(b, off, ret));
            }
            return ret;
        }

    } catch(e) { console.log("[-] Java Socket Hook Error: " + e); }

    // ====================================================================
    // 2. NATIVE SSL (PLAINTEXT TRAFFIC)
    // ====================================================================
    setTimeout(function() {
        console.log("[*] Enabling Native SSL Hooks (for Plaintext)...");
        var libs = ["libssl.so", "libboringssl.so", "libconscrypt.so"];
        
        libs.forEach(function(lib) {
            var m = Process.findModuleByName(lib);
            if (m) {
                var funcs = ["SSL_write", "SSL_read"];
                funcs.forEach(function(fname) {
                    var ptr = Module.findExportByName(lib, fname);
                    if (ptr) {
                        try {
                            Interceptor.attach(ptr, {
                                onEnter: function(args) {
                                    if(fname==="SSL_write") {
                                        var len = args[2].toInt32();
                                        if (len>0) {
                                            var buf = args[1].readByteArray(Math.min(len, 2048));
                                            var u8 = new Uint8Array(buf);
                                            var str="";
                                            for(var i=0;i<u8.length;i++) {
                                                var c=u8[i];
                                                if((c>=32&&c<=126)||c==10||c==13) str+=String.fromCharCode(c); else str+=".";
                                            }
                                            if (str.match(/^(GET|POST|PUT|DELETE|HTTP\/)/)) {
                                                console.log("\n� [Native-SSL] " + fname + " in " + lib + "\n" + str);
                                            }
                                        }
                                    } else { this.buf=args[1]; }
                                },
                                onLeave: function(retval) {
                                    if(fname==="SSL_read" && this.buf) {
                                        var len = retval.toInt32();
                                        if(len>0) {
                                            var buf = this.buf.readByteArray(Math.min(len, 2048));
                                            var u8 = new Uint8Array(buf);
                                            var str="";
                                            for(var i=0;i<u8.length;i++) {
                                                var c=u8[i];
                                                if((c>=32&&c<=126)||c==10||c==13) str+=String.fromCharCode(c); else str+=".";
                                            }
                                            if (str.match(/^(HTTP\/|{)/)) {
                                                 console.log("\n🔓 [Native-SSL] " + fname + " in " + lib + "\n" + str);
                                            }
                                        }
                                    }
                                }
                            });
                        } catch(e) {}
                    }
                });
            }
        });
    }, 1000);

});
