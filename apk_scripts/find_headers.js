/*
 * Header Setter Hunter
 * Scans classes in 'p810o' package (OkHttp) for methods like:
 *   func(String key, String value)
 * to find where headers are added.
 */

Java.perform(function() {
    console.log("[*] 🔍 Scanning 'p810o' package for addHeader methods...");

    // Common header keys to watch for
    var INTERESTING_KEYS = ["Authorization", "User-Agent", "Content-Type", "Accept", "Cookie"];

    // We'll scan verified loaded classes from the 'p810o' package
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith("p810o.") || className.startsWith("o.")) { 
                // Note: JADX says 'package p810o', but smali might just be 'o.X'
                // Based on previous logs, classes are likle 'o.a', 'o.b', etc.
                // Let's target strictly 'o.' based on your last JADX dump output
                
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();

                    for (var i = 0; i < methods.length; i++) {
                        var m = methods[i];
                        var args = m.getParameterTypes();

                        // We are looking for: method(String, String)
                        if (args.length === 2 && 
                            args[0].getName() === "java.lang.String" && 
                            args[1].getName() === "java.lang.String") {
                            
                            var methodName = m.getName();
                            
                            // Hook it!
                            // Need to safely handle overloads
                            try {
                                cls[methodName].overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
                                    // Check if this looks like a header
                                    if (k && INTERESTING_KEYS.includes(k)) {
                                        console.log("\n[+] 🎯 FOUND HEADER SETTER!");
                                        console.log("    Class: " + className);
                                        console.log("    Method: " + methodName);
                                        console.log("    Key: " + k);
                                        console.log("    Value: " + v);
                                    }
                                    return this[methodName](k, v);
                                }
                            } catch(e) {}
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[*] Hooking complete. Trigger network requests now!");
        }
    });
});
