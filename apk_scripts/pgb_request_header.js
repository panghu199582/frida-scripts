/*
 * Global List Hijack (The "Doomsday" Option)
 * 
 * Strategy:
 * Hook java.util.Collections.unmodifiableList (or Arrays.asList)
 * Scan EVERY list created in the app.
 * If a list contains Protocol.H2, we NUKE it and replace it with HTTP/1.1.
 * 
 * Target: OkHttp uses Util.immutableList or Arrays.asList to set protocols.
 */

Java.perform(function() {
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }
    console.log("[*] ☢️ INIT: GLOBAL PROTOCOL HIJACK ACTIVE");
    console.log("[*] Warning: This hooks extremely common methods. Expect log spam or lag.");

    try {
        var Collections = Java.use("java.util.Collections");
        var Arrays = Java.use("java.util.Arrays");
        var ArrayList = Java.use("java.util.ArrayList");

        // Helper to check if a list contains H2 protocol
        function isProtocolList(list) {
            if (!list || list.size() === 0) return false;
            try {
                // Check first element type
                var item = list.get(0);
                if (!item) return false;
                var str = item.toString();
                // Standard OkHttp Protocol.toString() returns "h2", "http/1.1", etc.
                if (str === "h2" || str === "http/1.1" || str === "spdy/3.1" || str === "h2_prior_knowledge") {
                    return true;
                }
            } catch(e) {}
            return false;
        }

        // Helper: Find HTTP/1.1 Enum from the same class as the h2 enum
        function getHttp11(h2Enum) {
            try {
                var EnumClass = h2Enum.getClass();
                var methodValues = EnumClass.getMethod("values", []);
                var values = methodValues.invoke(null, []);
                for(var k=0; k<values.length; k++) {
                    var v = values[k];
                    if (v.toString() === "http/1.1" || v.toString() === "HTTP_1_1") {
                        return v;
                    }
                }
            } catch(e) {}
            return null;
        }

        // Hook 1: java.util.Collections.unmodifiableList (Used by OkHttp Builder)
        // Careful: This is called millions of times. We need a very fast check.
        Collections.unmodifiableList.overload('java.util.List').implementation = function(list) {
            if (list && list.size() > 0) {
                 // Fast check: Is it our protocols list?
                 if (isProtocolList(list)) {
                     var hasH2 = false;
                     var h2Enum = null;
                     for(var i=0; i<list.size(); i++) {
                         var s = list.get(i).toString();
                         if (s === "h2" || s === "h2_prior_knowledge") {
                             hasH2 = true;
                             h2Enum = list.get(i);
                             break;
                         }
                     }

                     if (hasH2 && h2Enum) {
                         console.log("[!] ☢️ Intercepted H2 Protocol List creation!");
                         var http11 = getHttp11(h2Enum);
                         if (http11) {
                             console.log("    -> Replaced with [HTTP/1.1]");
                             // Return a new list with only HTTP/1.1
                             var newList = ArrayList.$new();
                             newList.add(http11);
                             return this.unmodifiableList(newList);
                         }
                     }
                 }
            }
            return this.unmodifiableList(list);
        };

        // Hook 2: Arrays.asList (Commonly used to create protocol lists)
        Arrays.asList.overload('[Ljava.lang.Object;').implementation = function(arr) {
            if (arr && arr.length > 0) {
                var hasH2 = false;
                var h2Enum = null;
                var http11Enum = null;
                
                for(var i=0; i<arr.length; i++) {
                    var item = arr[i];
                    if (item) {
                        var s = item.toString();
                        if (s === "h2" || s === "h2_prior_knowledge") {
                            hasH2 = true;
                            h2Enum = item;
                        } else if (s === "http/1.1" || s === "HTTP_1_1") {
                            http11Enum = item;
                        }
                    }
                }

                if (hasH2) {
                    // console.log("[!] ☢️ Intercepted H2 in Arrays.asList!");
                    if (http11Enum) {
                         // Create new array with only http/1.1
                         // Make sure type matches
                         var newArr = Java.array("java.lang.Object", [http11Enum]); 
                         // Note: We need to cast back to specific Enum array type if possible, 
                         // but Arrays.asList takes Object[], so this might pass.
                         // However, if the caller expects List<Protocol>, returning List<Object> is fine in Java runtime (erasure),
                         // but standard Java.array creates specific type.
                         
                         // Safer: Just modify the input array in place? No, unsafe.
                         // Let's call original with new array.
                         return this.asList(newArr);
                    } else if (h2Enum) {
                        // Try to find http11 from h2Enum class
                         var http11 = getHttp11(h2Enum);
                         if (http11) {
                             var newArr = Java.array("java.lang.Object", [http11]);
                             return this.asList(newArr);
                         }
                    }
                }
            }
            return this.asList(arr);
        };
        
    } catch(e) {
        console.log("[-] Hook Error: " + e);
    }
});

// Also include the existing monitoring for verification
setTimeout(function() {
    var lib = "libssl.so";
    var ssl_write = Module.findExportByName(lib, "SSL_write");
    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 0) {
                    var buf = args[1].readByteArray(len);
                    var u8 = new Uint8Array(buf);
                    var str = "";
                    for(var i=0; i<Math.min(len, 512); i++) {
                        var c = u8[i];
                        if((c>=32&&c<=126)||c==10) str+=String.fromCharCode(c);
                        else str+=".";
                    }
                    if (str.match(/^(GET|POST) /)) console.log("\n🚀 [REQ] " + str);
                    if (str.startsWith("PRI * HTTP/2")) console.log("\n⚠️ [H2] Still Active!");
                }
            }
        });
    }
}, 1000);
