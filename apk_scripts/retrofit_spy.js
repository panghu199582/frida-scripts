/*
 * Retrofit Spy / Interface Monitor
 * Intercepts java.lang.reflect.Proxy to log all API method calls and arguments.
 * Bypasses SSL, HTTP/2, and Pinning entirely by capturing data at the application layer.
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
    console.log("[*] 🕵️ Starting Retrofit Spy...");

    var Proxy = Java.use("java.lang.reflect.Proxy");
    var InvocationHandler = Java.use("java.lang.reflect.InvocationHandler");
    var Arrays = Java.use("java.util.Arrays");

    // Hook Proxy.newProxyInstance to intercept Interface creation
    Proxy.newProxyInstance.overload('java.lang.ClassLoader', '[Ljava.lang.Class;', 'java.lang.reflect.InvocationHandler')
        .implementation = function(loader, interfaces, originalHandler) {
            
            // Check if this proxy is relevant (filter out system stuff)
            var isTarget = false;
            var interfaceNames = [];
            
            for (var i = 0; i < interfaces.length; i++) {
                var name = interfaces[i].getName();
                interfaceNames.push(name);
                // Filter: Only look for app's package or obfuscated classes (short names like 'o.x')
                if (!name.startsWith("java.") && !name.startsWith("android.") && !name.startsWith("com.google.")) {
                    isTarget = true;
                }
            }

            if (isTarget) {
                console.log("[+] Intercepting Proxy for: " + interfaceNames.join(", "));
                
                // create a Custom Handler that wraps the original
                var MyHandler = Java.registerClass({
                    name: 'com.example.RetrofitSpy$' + Math.random().toString(36).substring(7),
                    implements: [InvocationHandler],
                    fields: {
                        original: 'java.lang.reflect.InvocationHandler'
                    },
                    methods: {
                        invoke: function(proxy, method, args) {
                            var methodName = method.getName();
                            
                            // Filter out generic Object methods
                            if (methodName !== 'toString' && methodName !== 'hashCode' && methodName !== 'equals') {
                                var output = "\n🔌 [API CALL] " + interfaceNames[0] + "." + methodName + "()";
                                
                                // Print Arguments
                                if (args) {
                                    for (var j = 0; j < args.length; j++) {
                                        var arg = args[j];
                                        var argStr = "null";
                                        if (arg !== null) {
                                            argStr = arg.toString();
                                            // Optional: Pretty print JSON arguments if needed
                                        }
                                        output += "\n    Arg[" + j + "]: " + argStr;
                                        
                                        // Highlight Token
                                        if (argStr.includes("Bearer") || (argStr.length > 20 && !argStr.includes(" "))) {
                                           // Heuristic for token
                                        }
                                    }
                                }
                                console.log(output);
                            }

                            // Call original
                            return this.original.value.invoke(proxy, method, args);
                        }
                    }
                });

                var wrapper = MyHandler.$new();
                wrapper.original.value = originalHandler;
                
                return this.newProxyInstance(loader, interfaces, wrapper);
            }

            return this.newProxyInstance(loader, interfaces, originalHandler);
        };
});

// Keep existing SSL Logger active as a backup
setTimeout(function() {
    // Just a simple SSL Logger to correlate
    var lib = "libssl.so";
    var ssl_write = Module.findExportByName(lib, "SSL_write");
    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(a) {
                var len = a[2].toInt32();
                if (len > 0) {
                   var s = "";
                   var d = a[1].readByteArray(len);
                   var u = new Uint8Array(d);
                   for(var i=0;i<Math.min(len,100);i++) s+=String.fromCharCode(u[i]);
                   if(s.includes("HTTP/1")) console.log("🚀 [SSL] Request Sent");
                }
            }
        });
    }
}, 1000);
