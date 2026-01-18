
/*
 * Listener Tracer
 * Goal: Find out who is listening on the local ports that libalib connects to.
 */

function getModuleName(addr) {
    if (!addr) return "Unknown";
    var mod = Process.findModuleByAddress(addr);
    if (mod) return mod.name + " (" + mod.base + ") + " + (addr.sub(mod.base));
    return "Unknown(" + addr + ")";
}

Java.perform(function() {
    console.log("[*] 🎧 Monitoring Bind/Listen/Accept to find the Local Server...");

    // Helper to print IP:Port
    function logSockAddr(funcName, fd, sockAddr) {
        try {
            var family = sockAddr.readU16();
            if (family === 2) { // AF_INET
                var port = ((sockAddr.add(2).readU16() & 0xFF) << 8) | ((sockAddr.add(2).readU16() >> 8) & 0xFF);
                var ip = [];
                for(var i=0;i<4;i++) ip.push(sockAddr.add(4+i).readU8());
                var ipStr = ip.join(".");
                
                console.log("  👉 " + funcName + "(FD=" + fd + ") on " + ipStr + ":" + port);
            }
        } catch(e) {}
    }
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    // 1. Hook Bind (Who reserves the port?)
    var bindPtr = Module.findExportByName("libc.so", "bind");
    if (bindPtr) {
        Interceptor.attach(bindPtr, {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                var addr = args[1];
                this.addr = addr;
                this.fd = fd;
            },
            onLeave: function(ret) {
                if (ret.toInt32() === 0) {
                     var caller = getModuleName(this.returnAddress);
                     console.log("\n🔒 [BIND] SUCCESS by " + caller);
                     logSockAddr("bind", this.fd, this.addr);
                }
            }
        });
    }

    // 2. Hook Listen (Who enables connections?)
    var listenPtr = Module.findExportByName("libc.so", "listen");
    if (listenPtr) {
        Interceptor.attach(listenPtr, {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                var caller = getModuleName(this.returnAddress);
                console.log("\n👂 [LISTEN] on FD=" + fd + " by " + caller);
            }
        });
    }
    
    // 3. Hook Accept (Who accepts the connection from libalib?)
    var acceptPtr = Module.findExportByName("libc.so", "accept");
    if (acceptPtr) {
        Interceptor.attach(acceptPtr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
            },
            onLeave: function(ret) {
                var clientFD = ret.toInt32();
                if (clientFD > 0) {
                    var caller = getModuleName(this.returnAddress);
                    console.log("\n🤝 [ACCEPT] New Connection! Server FD=" + this.fd + " -> Client FD=" + clientFD);
                    console.log("   Handled by: " + caller);
                }
            }
        });
    }
    
    // 4. Also bypass libalib just in case it crashes
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

});
