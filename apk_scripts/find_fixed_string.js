
Java.perform(function() {
    var TARGET = "1665464363240-dbb1-7c53-6cfe";
    console.log("[*] 🎯 Hunting for String: " + TARGET);

    var StringClass = Java.use("java.lang.String");
    var StringBuilder = Java.use("java.lang.StringBuilder");

    // 1. Hook String Constructors (UTF-8 bytes)
    StringClass.$init.overload('[B', 'java.nio.charset.Charset').implementation = function(b, charset) {
        var ret = this.$init(b, charset);
        var s = this.toString();
        if (s.indexOf(TARGET) !== -1) {
            console.log("\n[!] 🚨 String Detected (Constructor-Charset)!");
            console.log("    Value: " + s);
            console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return ret;
    }

    // 2. Hook String Constructors (Bytes only)
    StringClass.$init.overload('[B').implementation = function(b) {
        var ret = this.$init(b);
        var s = this.toString();
        if (s.indexOf(TARGET) !== -1) {
            console.log("\n[!] 🚨 String Detected (Constructor-Bytes)!");
            console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return ret;
    }

    // 3. Hook StringBuilder.toString() (Very common for generated strings)
    StringBuilder.toString.implementation = function() {
        var s = this.toString();
        if (s.indexOf(TARGET) !== -1) {
             console.log("\n[!] 🚨 StringBuilder Generated Target!");
             console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return s;
    }

    // 4. Hook String.valueOf (Common for conversions)
    StringClass.valueOf.overload('java.lang.Object').implementation = function(obj) {
        var s = this.valueOf(obj);
        if (s && s.toString().indexOf(TARGET) !== -1) {
             console.log("\n[!] 🚨 String.valueOf Detected!");
             console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return s;
    }
    
    console.log("[*] Hooks active. Trigger the app logic now.");
});
