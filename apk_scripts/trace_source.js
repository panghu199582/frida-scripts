
/*
 * High-Level Network Tracer to Identify Source of Requests
 * This script hooks low-level socket functions to find WHICH library is opening connections.
 */

function getModuleName(addr) {
    var mod = Process.findModuleByAddress(addr);
    if (mod) return mod.name + " (" + mod.base + ") + " + (addr.sub(mod.base));
    return "Unknown(" + addr + ")";
}

// Helper to format IP
function ntohs(val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

function getExactModuleName(pcElement) {
    if (!pcElement) return "Unknown";
    var ptrVal = ptr(pcElement);
    var mod = Process.findModuleByAddress(ptrVal);
    if (mod) return mod.name;
    return "Unknown";
}
if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        this.sockAddr = args[1];
        this.addrLen = args[2].toInt32();
        
        // Parse sockaddr_in (IPv4)
        if (this.addrLen >= 16) {
            var family = this.sockAddr.readU16();
            if (family === 2) { // AF_INET
                var port = ntohs(this.sockAddr.add(2).readU16());
                var ip = this.sockAddr.add(4).readByteArray(4);
                var ipStr = new Uint8Array(ip).join(".");
                
                // Filter out local stuff if needed, but for now capture all
                this.dest = ipStr + ":" + port;
                
                // KEY PART: Who is calling connect?
                var lr = this.returnAddress; 
                var caller = getModuleName(lr);
                
                console.log("\n🔗 [CONNECT] FD:" + this.sockfd + " -> " + this.dest);
                console.log("    |_ Call Origin: " + caller);
                
                // Print a small backtrace to see the chain
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n    | ");
                console.log("    |_ Stack:\n    | " + bt.substring(0, 1000)); // Limit output
            }
        }
    }
});

/*
 * Also hook 'send'/'write' just to see data roughly and correlate with FD
 */
var send_onEnter = function(args) {
    var fd = args[0].toInt32();
    var buf = args[1];
    var len = args[2].toInt32();
    
    // Only look at typical HTTP/TLS length or specific FDs if we tracked them
    // For now, simple check: is it a ClientHello or HTTP?
    if (len > 0) {
        // Read stats first without copying everything
        // 0x16 = Handshake, 0x03 = SSL version... (TLS Client Hello starts with 16 03 ...)
        // HTTP starts with GET/POST/etc
        
        // We can't cheaply check content for EVERY write, so let's rely on the backtrace of 'connect' mostly.
        // But if we want to confirm if it's SSL:
        
        // var header = buf.readByteArray(3);
        // var u8 = new Uint8Array(header);
        // if (u8[0] === 0x16 && u8[1] === 0x03) {
        //     console.log("    Sending TLS Handshake on FD " + fd);
        // }
    }
}
// Interceptor.attach(Module.findExportByName("libc.so", "send"), { onEnter: send_onEnter });
// Interceptor.attach(Module.findExportByName("libc.so", "write"), { onEnter: send_onEnter });

console.log("[*] 🕵️ Traffic Source Tracer Active. Perform Login now!");
