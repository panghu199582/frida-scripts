/*
 * Universal OkHttp3 Monitor
 * Dynamically finds the Interceptor Chain to monitor all requests/responses.
 */

Java.perform(function() {
    console.log("[*] Starting Universal OkHttp Monitor...");

    function printHeaders(headers, label) {
        if (!headers) return;
        var str = headers.toString();
        // Beautify output
        var lines = str.split("\n");
        console.log(label + " Headers:");
        lines.forEach(function(l) {
            if (l.trim().length > 0) console.log("   " + l.trim());
        });
    }

    function printBody(body, label) {
        if (!body) return;
        try {
            var Buffer = Java.use("okio.Buffer");
            var buffer = Buffer.$new();
            body.writeTo(buffer);
            var content = buffer.readUtf8();
            if (content.length > 0) {
                console.log(label + " Body (" + content.length + "b):");
                // Print first 2KB cleanly
                console.log(content.substring(0, 2048)); 
                if (content.length > 2048) console.log("   ... (truncated)");
            }
        } catch(e) {
            // console.log("   [Binary/Stream Body]");
        }
    }

    function hookInterceptorChain(className) {
        try {
            var Chain = Java.use(className);
            var proceedMethod = null;

            // Find 'proceed' method: usually takes 1 arg (Request) and returns Response
            var methods = Chain.class.getDeclaredMethods();
            for(var i=0; i<methods.length; i++) {
                var m = methods[i];
                if (m.getParameterTypes().length === 1) {
                    var retType = m.getReturnType().getName();
                    var paramType = m.getParameterTypes()[0].getName();
                    // Check for standard or potential obfuscated signatures
                    // Standard: proceed(okhttp3.Request) -> okhttp3.Response
                    if ((paramType.indexOf("Request") !== -1 || paramType.indexOf(".a0") !== -1 || paramType.indexOf("a0") !== -1) && 
                        (retType.indexOf("Response") !== -1)) {
                         proceedMethod = m.getName();
                         break;
                    }
                }
            }

            if (proceedMethod) {
                console.log("[+] Found Chain Method: " + className + "." + proceedMethod);
                
                Chain[proceedMethod].overloads[0].implementation = function(req) {
                    // --- REQUEST ---
                    try {
                        console.log("\n=================== 🚀 REQUEST ===================");
                        console.log("URL: " + req.url());
                        console.log("Method: " + req.method());
                        printHeaders(req.headers(), "Req");
                        printBody(req.body(), "Req");
                    } catch(e) { console.log("[-] Req Print Error: " + e); }

                    // --- EXECUTE ---
                    var resp = this[proceedMethod](req);

                    // --- RESPONSE ---
                    try {
                        console.log("\n=================== ⬇️ RESPONSE ===================");
                        console.log("Code: " + resp.code() + " " + resp.message());
                        console.log("URL: " + resp.request().url());
                        printHeaders(resp.headers(), "Resp");
                        
                        // Body Peeking
                        var respBody = resp.body();
                        if (respBody) {
                             // Limit peek to 1MB
                             var peeked = resp.peekBody(1024 * 1024); 
                             var string = peeked.string();
                             if (string.length > 0) {
                                 console.log("Resp Body (" + string.length + "b):");
                                 if (string.length > 2000) {
                                     console.log(string.substring(0, 2000) + "\n   ... (truncated)");
                                 } else {
                                     console.log(string);
                                 }
                             }
                        }
                    } catch(e) { console.log("[-] Resp Print Error: " + e); }

                    return resp;
                }
                return true;
            }
        } catch(e) {
            // console.log("[-] Failed to hook " + className + ": " + e);
        }
        return false;
    }

    // 1. Try Standard Names
    var candidates = [
        "okhttp3.internal.http.RealInterceptorChain",
        "okhttp3.internal.connection.RealInterceptorChain" // okhttp 4.x
    ];

    var hooked = false;
    for (var i=0; i<candidates.length; i++) {
        if (hookInterceptorChain(candidates[i])) {
            hooked = true;
            break;
        }
    }

    // 2. Search if not found
    if (!hooked) {
        console.log("[*] Searching for Obfuscated Chains...");
        Java.enumerateLoadedClasses({
            onMatch: function(name) {
                if (name.startsWith("okhttp3.") && name.includes("InterceptorChain")) {
                    hookInterceptorChain(name);
                }
                // Check for 'o.a0' wrapper or similar if known (from pgb.js context)
            },
            onComplete: function() {
                // If nothing found, try bruteforce finding the specific known class
                // Based on user feedback: "okhttp 4.5.0"
                if (!hooked) {
                     // Try specific 4.x path again explicitly inside perform
                     try {
                         hookInterceptorChain("okhttp3.internal.connection.RealInterceptorChain"); 
                     } catch(e){}
                }
            }
        });
    }

    // 3. Last Resort: o.a0 (Request) & o.a0 (Client) Hooks from previous knowledge
    // This hooks the 'newCall' or 'execute' equivalent on the Client
    try {
        // Based on pgb.js, 'o.a0' seemed to be the Client or Call.
        // Let's hook Request.Builder to catch all Request creations as a fallback
        var ReqBuilder = Java.use("okhttp3.Request$Builder");
        ReqBuilder.build.implementation = function() {
            var req = this.build();
            // console.log("[Request$Builder] Created: " + req.url());
            return req;
        }
    } catch(e) {}

});
