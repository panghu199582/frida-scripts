/*
 * Precision Java Downgrade (Target: o.a) - Fixed for Frida 17+
 * Forces HTTP/1.1 by modifying the Constructor of the 'Address' class.
 */

Java.perform(function() {
    console.log("[*] 🎯 Targeting obfuscated class: o.a");

    try {
        var TargetClass = Java.use("o.a");
        var Arrays = Java.use("java.util.Arrays");
        
        // Hook all constructors
        var overloads = TargetClass.$init.overloads;
        
        overloads.forEach(function(ctor) {
            ctor.implementation = function() {
                var args = arguments;
                
                // IMPORTANT: In Frida, 'arguments' is object, not Array.
                // We MUST convert it to a proper array to modify it safely.
                // And we must preserve the exact types/values.
                var newArgs = [].slice.call(args);

                var modified = false;

                // Index 9 is 'protocols' (List) based on JADX analysis
                var PROTO_INDEX = 9;

                if (newArgs.length > PROTO_INDEX) {
                    var list = newArgs[PROTO_INDEX];
                    
                    // Check if it is a list and has content
                    // Note: 'list' is a valid Java wrapper here.
                    if (list) {
                        try {
                             if (list.size() > 0) {
                                 var protoEnum0 = list.get(0);
                             var EnumClass = protoEnum0.getClass();
                             var methodValues = EnumClass.getMethod("values", []);
                             var values = methodValues.invoke(null, []);
                             
                             var http11 = null;
                             // Find HTTP/1.1 enum
                             for(var k=0; k<values.length; k++) {
                                 var v = values[k];
                                 if (v.toString() == "http/1.1" || v.toString() == "HTTP_1_1") {
                                     http11 = v;
                                     break;
                                 }
                             }

                             if (http11) {
                                 console.log("[+] 🟢 Found HTTP/1.1 Enum, replacing protocols...");
                                 newArgs[PROTO_INDEX] = Arrays.asList([http11]);
                                 modified = true;
                             }
                           }
                        } catch(e) {
                             console.log("[-] Error forcing proto: " + e);
                        }
                    }
                }

                // Call original constructor with (potentially) modified args
                return this.$init.apply(this, newArgs);
            }
        });
        
        console.log("[+] Hooked o.a Constructor(s) successfully.");

    } catch(e) {
        console.log("[-] Hook failed: " + e);
    }
});
