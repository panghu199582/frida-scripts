
Java.perform(function() {
    console.log("[*] File Reader Monitor Started...");

    var FileInputStream = Java.use("java.io.FileInputStream");
    var StringClass = Java.use("java.lang.String");
    
    // Hook FileInputStream.read(byte[])
    FileInputStream.read.overload('[B').implementation = function(b) {
        var ret = this.read(b);
        if (ret > 0) {
            var s = StringClass.$new(b, 0, ret);
            if (s.indexOf("dbb1-7c53") !== -1) { // Partial UUID match
                console.log("\n[!] 🚨 Found UUID in File Read!");
                // Try to get file descriptor or name? Hard in FIS.
                // But we can print stack to see WHO is reading.
                console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            }
        }
        return ret;
    }

    console.log("[*] Waiting for file reads...");
});
