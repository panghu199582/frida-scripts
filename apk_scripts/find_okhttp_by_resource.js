// Find Obfuscated OkHttp by Resource Loading
// specifically looking for "publicsuffixes.gz"

function traceResourceLoading() {
    Java.perform(function() {
        console.log("=== Tracing getResourceAsStream for 'publicsuffixes.gz' ===");

        var Class = Java.use("java.lang.Class");
        var ClassLoader = Java.use("java.lang.ClassLoader");

        // Hook Class.getResourceAsStream
        Class.getResourceAsStream.overload('java.lang.String').implementation = function(path) {
            if (path && path.indexOf("publicsuffixes.gz") !== -1) {
                console.log("\n[!] HIT: 'publicsuffixes.gz' loaded!");
                console.log("    Path: " + path);
                console.log("    Loader Class: " + this.getName());
                
                // Print Stack Trace to find the caller (the obfuscated OkHttp class)
                var Exception = Java.use("java.lang.Exception");
                var Log = Java.use("android.util.Log");
                console.log("    Stack Trace:\n" + Log.getStackTraceString(Exception.$new()));
            }
            return this.getResourceAsStream(path);
        };

        // Also Hook ClassLoader.getResourceAsStream just in case
        ClassLoader.getResourceAsStream.overload('java.lang.String').implementation = function(path) {
             if (path && path.indexOf("publicsuffixes.gz") !== -1) {
                console.log("\n[!] HIT (ClassLoader): 'publicsuffixes.gz' loaded!");
                console.log("    Path: " + path);
                
                var Exception = Java.use("java.lang.Exception");
                var Log = Java.use("android.util.Log");
                console.log("    Stack Trace:\n" + Log.getStackTraceString(Exception.$new()));
            }
            return this.getResourceAsStream(path);
        };
        
        console.log("[*] Hooks installed. Please trigger a network request now...");
    });
}

setTimeout(traceResourceLoading, 500);
