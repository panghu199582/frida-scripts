
/*
 * Java Socket Monitor
 * 
 * Works even if OkHttp is obfuscated because OkHttp eventually uses 
 * java.net.Socket and javax.net.ssl.SSLSocket.
 */

Java.perform(function() {
    console.log("[*] ☕ Java Socket Monitor Active");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    // ====================================================================
    // 1. ANT-DETECTION BYPASS (DISABLED - Causing Crash)
    // ====================================================================
    // The previous pthread_create hook (both replace and attach) caused SIGSEGV.
    // We are temporarily disabling it to check if Java hooks can work alone
    // or if we need a different bypass strategy (e.g. signal suppression).
    console.log("[*] ⚠️ Native Bypass Disabled (Stability Check)");

    // ====================================================================
    // 2. SOCKET OUTPUT/INPUT STREAM HOOKING
    // ====================================================================
    
    // Helper to log byte arrays
    function logData(prefix, data, len) {
        if (len <= 0) return;
        
        // Convert to string
        var str = "";
        for(var i=0; i<Math.min(len, 4096); i++) {
            var c = data[i];
            if((c >= 32 && c <= 126) || c == 10 || c == 13) str += String.fromCharCode(c);
            else str += ".";
        }
        
        // Filter: Only log if it looks like HTTP or JSON
        if (str.includes("HTTP/") || str.includes("POST") || str.includes("GET") || str.includes("{") || str.includes("Keep-Alive")) {
             console.log("\n" + prefix + " (" + len + "b):\n" + str);
        }
    }

    // Hook OutputStream.write()
    // We hook the base class to catch everything
    var OutputStream = Java.use("java.io.OutputStream");
    
    // overload 1: write(byte[])
    OutputStream.write.overload('[B').implementation = function(b) {
        logData("⬆️ [JavaStream] Write", b, b.length);
        return this.write(b);
    }
    
    // overload 2: write(byte[], int, int)
    OutputStream.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
        var sub = Java.array('byte', b).slice(off, off+len);
        logData("⬆️ [JavaStream] Write", sub, len);
        return this.write(b, off, len);
    }

    // Hook InputStream.read()
    var InputStream = Java.use("java.io.InputStream");
    
    // overload: read(byte[], int, int)
    InputStream.read.overload('[B', 'int', 'int').implementation = function(b, off, len) {
        var ret = this.read(b, off, len);
        if (ret > 0) {
            var sub = Java.array('byte', b).slice(off, off+ret);
            logData("⬇️ [JavaStream] Read", sub, ret);
        }
        return ret;
    }
    
    console.log("[+] OutputStream/InputStream hooks installed.");

});
