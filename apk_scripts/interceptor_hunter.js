/*
 * OkHttp Interceptor Hunter
 * Scans object instances to find RealCall and hooks the interceptor chain.
 * This captures FINAL Request (with all headers added) and RAW Response.
 */

Java.perform(function() {
    console.log("[*] 🦈 Interceptor Hunter Started...");

    // We scan for the RealCall class.
    // RealCall usually has methods: execute(), enqueue()
    // It holds: client, originalRequest

    // Heuristic: Find a class that has "getResponseWithInterceptorChain" logic.
    // It adds interceptors to a list.

    // Let's try to find potential 'Chain' interfaces first.
    // Interface with method: proceed(Request) -> Response
    
    // Scan all loaded classes in 'o' package
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith("o.") && className.length < 10) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    
                    for (var i = 0; i < methods.length; i++) {
                        var m = methods[i];
                        var args = m.getParameterTypes();
                        var retType = m.getReturnType().getName();
                        
                        // Look for: Response foo(Chain)
                        // Chain is an interface inside the same package usually
                        if (args.length === 1 && retType.startsWith("o.")) {
                            var argType = args[0].getName();
                            
                            // Check if argType is an interface (The Chain)
                            // We can't easily check isInterface in Frida without loading, but we can guess.
                            if (argType.startsWith("o.") && argType !== className) {
                                // Potential Interceptor.intercept(Chain)
                                // Let's hook it and see if it yields headers
                                
                                try {
                                    if (!cls.$isInterface) { // Only hook implementation classes
                                        m.setAccessible(true);
                                        var mName = m.getName();
                                        
                                        // Overload handling
                                        cls[mName].overload(argType).implementation = function(chain) {
                                            // console.log("[?] Hit potential interceptor: " + className + "." + mName);
                                            
                                            // 1. Try to get Request from Chain
                                            // chain.request() // method name unknown
                                            // Reflectively scan Chain for request() method (returns Request)
                                            var request = null;
                                            try {
                                                var chainMethods = chain.getClass().getDeclaredMethods();
                                                for(var k=0; k<chainMethods.length; k++) {
                                                    var cm = chainMethods[k];
                                                    if (cm.getParameterTypes().length === 0 && cm.getReturnType().getName().startsWith("o.")) {
                                                        // Potential request() getter
                                                        var potentialReq = cm.invoke(chain, []);
                                                        if (potentialReq && potentialReq.toString().toLowerCase().includes("http")) { // Request.toString() usually has URL
                                                            request = potentialReq;
                                                            break;
                                                        }
                                                    }
                                                }
                                            } catch(e) {}

                                            if (request) {
                                                console.log("\n⚡ [INTERCEPTOR] " + className);
                                                console.log("    Request: " + request.toString());
                                                
                                                // Try to dump headers from Request object
                                                // Request usually has a 'headers' field (Headers class)
                                                // Reflectively dump string fields/methods
                                                try {
                                                    var reqStr = request.toString();
                                                    // Request headers often printed in toString() or we can verify class info
                                                    // console.log("    Details: " + reqStr);
                                                } catch(e){}
                                            }

                                            // 2. Call original (proceed)
                                            var response = this[mName](chain);

                                            // 3. Inspect Response
                                            if (response) {
                                                 // console.log("    Response: " + response.toString());
                                                 // If we found a request, this is likely a response
                                            }
                                            
                                            return response;
                                        }
                                    }
                                } catch(e) {}
                            }
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[*] Scan & Hook complete. Checking traffic...");
        }
    });
});
