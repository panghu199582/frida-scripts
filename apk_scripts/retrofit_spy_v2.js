/*
 * Retrofit Spy V2 - Request & Response Monitor
 * Intercepts java.lang.reflect.Proxy to log API calls AND their return values.
 * Compatible with suspend functions (Continuation) and standard calls.
 */

if (!Module.findExportByName) {
    Module.findExportByName = function (moduleName, exportName) {
        if (moduleName === null) return Module.findGlobalExportByName(exportName);
        var mod = Process.findModuleByName(moduleName);
        return mod ? mod.findExportByName(exportName) : null;
    };
}

Java.perform(function() {
    console.log("[*] 🕵️ Starting Retrofit Spy V2 (Req + Res)...");

    var Proxy = Java.use("java.lang.reflect.Proxy");
    var InvocationHandler = Java.use("java.lang.reflect.InvocationHandler");

    Proxy.newProxyInstance.overload('java.lang.ClassLoader', '[Ljava.lang.Class;', 'java.lang.reflect.InvocationHandler')
        .implementation = function(loader, interfaces, originalHandler) {
            var isTarget = false;
            var interfaceNames = [];
            for (var i = 0; i < interfaces.length; i++) {
                var name = interfaces[i].getName();
                interfaceNames.push(name);
                if (!name.startsWith("java.") && !name.startsWith("android.") && !name.startsWith("com.google.")) {
                    isTarget = true;
                }
            }

            if (isTarget) {
                var MyHandler = Java.registerClass({
                    name: 'com.example.RetrofitSpy$' + Math.random().toString(36).substring(7),
                    implements: [InvocationHandler],
                    fields: { original: 'java.lang.reflect.InvocationHandler' },
                    methods: {
                        invoke: function(proxy, method, args) {
                            var methodName = method.getName();
                            if (methodName === 'toString') return this.original.value.invoke(proxy, method, args);

                            var output = "\n🔌 [API CALL] " + interfaceNames[0] + "." + methodName + "()";
                            
                            // 1. Log Arguments (Request)
                            if (args) {
                                for (var j = 0; j < args.length; j++) {
                                    var arg = args[j];
                                    var argStr = (arg === null) ? "null" : arg.toString();
                                    
                                    // Check for Kotlin Continuation (Callback for suspend functions)
                                    if (arg && arg.getClass().getName().includes("Continuation")) {
                                        // TODO: Hook Continuation to see async result? 
                                        // Difficult in generic proxy, but we can log that it's async.
                                        output += "\n    Arg[" + j + "] (Async Callback): " + argStr;
                                    } else {
                                        output += "\n    Arg[" + j + "]: " + argStr;
                                    }
                                }
                            }
                            console.log(output);

                            // 2. Call Original & Log Result (Response)
                            try {
                                var result = this.original.value.invoke(proxy, method, args);
                                
                                if (result !== null) {
                                    var resStr = result.toString();
                                    // Filter out non-informative toStrings
                                    if (!resStr.startsWith("java.lang.Object")) {
                                        console.log("    🔙 [RETURN] " + resStr);
                                    }
                                    
                                    // If result is an Observable/Single (RxJava), we might miss the real data.
                                    // But if it's a synchronous call or standard object, we got it.
                                }
                                return result;
                            } catch(e) {
                                console.log("    💥 [EXCEPTION] " + e);
                                throw e;
                            }
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
