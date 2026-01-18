Java.perform(function() {
    // ====================================================================
    // [PART 1] ANTI-DETECTION (CRITICAL)
    // ====================================================================
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }

    console.log("[*] Anti-Detection: Blocking libalib.so threads...");
    
    var libAlib = null;
    var linkerRequest = Process.findModuleByName("linker64") || Process.findModuleByName("linker");
    
    function isLibAlib(addr) {
        if (!libAlib) libAlib = Process.findModuleByName("libalib.so");
        if (libAlib) {
            var ptrVal = parseInt(addr);
            var base = parseInt(libAlib.base);
            var end = base + libAlib.size;
            return (ptrVal >= base && ptrVal < end);
        }
        return false;
    }

    var pthread_create_ptr = Module.findExportByName(null, "pthread_create");
    if (pthread_create_ptr) {
        Interceptor.replace(pthread_create_ptr, new NativeCallback(function(thread_ptr, attr, start_routine, arg) {
            if (isLibAlib(start_routine)) {
                // console.log("[!] BLOCKED thread creation from libalib.so! Entry: " + start_routine);
                return 0; // Success (fake)
            }
            var original = new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            return original(thread_ptr, attr, start_routine, arg);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    } else {
        console.log("[-] pthread_create hook failed!");
    }


    // ====================================================================
    // [PART 2] HTTP/2 DOWNGRADE (FORCE HTTP/1.1)
    // ====================================================================
    // This forces OkHttp to use HTTP/1.1 so SSL_read/write is human readable.
    try {
        var Collections = Java.use("java.util.Collections");
        var Arrays = Java.use("java.util.Arrays");
        var ArrayList = Java.use("java.util.ArrayList");

        function isProtocolList(list) {
            if (!list || list.size() === 0) return false;
            try {
                var item = list.get(0).toString();
                return (item === "h2" || item === "http/1.1" || item === "h2_prior_knowledge");
            } catch(e) {}
            return false;
        }

        function getHttp11(h2Enum) {
            try {
                var EnumClass = h2Enum.getClass();
                var values = EnumClass.getMethod("values", []).invoke(null, []);
                for(var k=0; k<values.length; k++) {
                    if (values[k].toString() === "http/1.1") return values[k];
                }
            } catch(e) {}
            return null;
        }

        // Hook Collections.unmodifiableList (Used by OkHttp Builder)
        Collections.unmodifiableList.overload('java.util.List').implementation = function(list) {
            if (list && list.size() > 0 && isProtocolList(list)) {
                var h2Enum = null;
                for(var i=0; i<list.size(); i++) {
                    if (list.get(i).toString() === "h2") {
                        h2Enum = list.get(i);
                        break;
                    }
                }
                if (h2Enum) {
                    console.log("[!] ☢️ Force-Downgrading HTTP/2 -> HTTP/1.1");
                    var http11 = getHttp11(h2Enum);
                    if (http11) {
                        var newList = ArrayList.$new();
                        newList.add(http11);
                        return this.unmodifiableList(newList);
                    }
                }
            }
            return this.unmodifiableList(list);
        };
        
        console.log("[+] HTTP/2 Downgrade Active");
    } catch(e) { console.log("[-] Downgrade Hook Error: " + e); }


    // ====================================================================
    // [PART 3] NATIVE SSL CAPTURE (THE REAL DATA)
    // ====================================================================
    // ====================================================================
    // [PART 3] NATIVE SSL CAPTURE (ENHANCED)
    // ====================================================================
    setTimeout(function() {
    var lib = "libssl.so";
    if (!Module.findExportByName(lib, "SSL_write")) {
        lib = "libmonochrome.so"; 
        if (!Module.findExportByName(lib, "SSL_write")) lib = "libcrypto.so"; 
    }

    var ssl_write = Module.findExportByName(lib, "SSL_write");
    var ssl_read = Module.findExportByName(lib, "SSL_read");
    var contextMap = {};

    function cleanStr(data, len) {
        var u8 = new Uint8Array(data);
        var str = "";
        // Read up to decent length to capture full headers/bodies
        var max = Math.min(len, 32768); 
        for(var i=0; i<max; i++) {
            var c = u8[i];
            // Allow tab, newline, carriage return, and printable ASCII
            if((c>=32&&c<=126)||c==10||c==13||c==9) str+=String.fromCharCode(c);
            else str+="."; 
        }
        return str;
    }

    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(args) {
                var sslPtr = args[0].toString();
                var len = args[2].toInt32();
                if (len > 0) {
                    var data = args[1].readByteArray(len);
                    var str = cleanStr(data, len);

                    // 1. Analyze Context (Method/URL)
                    var methodMatch = str.match(/^(GET|POST|PUT|DELETE|PATCH) ([^ ]+) HTTP/);
                    if (methodMatch) {
                        contextMap[sslPtr] = { 
                            method: methodMatch[1], 
                            path: methodMatch[2], 
                            host: "unknown",
                            fullUrl: null
                        };
                    }
                    var hostMatch = str.match(/Host: ([^\r\n]+)/i);
                    if (hostMatch && contextMap[sslPtr]) {
                        contextMap[sslPtr].host = hostMatch[1].trim();
                        contextMap[sslPtr].fullUrl = "https://" + contextMap[sslPtr].host + contextMap[sslPtr].path;
                    }

                    // 2. Prepare Log Prefix
                    var prefix = "[SSL Outgoing]";
                    if (contextMap[sslPtr]) {
                        if (contextMap[sslPtr].fullUrl) prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].fullUrl + "]";
                        else prefix = "[" + contextMap[sslPtr].method + " " + contextMap[sslPtr].path + "]";
                    }

                    // 3. Log Content
                    // If it looks like a new Request (has Method line), log as Headers
                    if (methodMatch) {
                        console.log("\n🚀 " + prefix + " Request Headers/Body:\n" + str);
                    } else {
                        // Otherwise it's likely a Body chunk (JSON, Form, etc)
                        // Only log if it has meaningful content
                        if (str.replace(/\./g, "").trim().length > 0) {
                             console.log("\n📤 " + prefix + " Request Body Chunk:\n" + str);
                        }
                    }
                }
            }
        });
    }

    if (ssl_read) {
        Interceptor.attach(ssl_read, {
            onEnter: function(args) {
                this.sslPtr = args[0].toString();
                this.buf = args[1];
            },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 0 && this.buf) {
                    var data = this.buf.readByteArray(len);
                    var str = cleanStr(data, len);
                    
                    var ctx = contextMap[this.sslPtr];
                    var prefix = ctx ? ("[" + ctx.method + " " + (ctx.fullUrl || ctx.path) + "]") : "[SSL Response]";

                    // Check if it's Headers or Body
                    if (str.startsWith("HTTP/1.1") || str.startsWith("HTTP/2")) {
                        console.log("\n⬅️ " + prefix + " Response Headers:\n" + str);
                    } else {
                        // Body chunk
                        if (str.replace(/\./g, "").trim().length > 0) {
                             console.log("\n⬇️ " + prefix + " Response Body Chunk:\n" + str);
                        }
                    }
                }
            }
        });
    }
    
    console.log("[+] 🛡️ Native SSL Monitoring Active (Full Traffic + URL Context)");
}, 1000);


    // ====================================================================
    // [PART 3] JAVA GZIP/CIPHER HOOKS (DISABLED FOR DEBUGGING)
    // ====================================================================
    // ====================================================================
    // [PART 4] JAVA OKHTTP LOGGING (BEST FOR THIS APP)
    // ====================================================================
    // Since we saw boot-okhttp.oat, we know it uses Java OkHttp.
    // Let's hook the RealCall.getResponseWithInterceptorChain or similar
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.RealCall");
        
        // Log Requests
        RealCall.execute.overload().implementation = function() {
            try {
                var req = this.request();
                console.log("\n📦 [OkHttp-Sync] " + req.method() + " " + req.url());
                logHeaders(req.headers());
            } catch(e) { console.log(e); }
            return this.execute();
        }

        RealCall.enqueue.overload('okhttp3.Callback').implementation = function(cb) {
            try {
                var req = this.request();
                console.log("\n📦 [OkHttp-Async] " + req.method() + " " + req.url());
                logHeaders(req.headers());
                
                // Wrap Callback to log Response
                var MyCallback = Java.registerClass({
                    name: "com.example.MyCallback",
                    implements: [Java.use("okhttp3.Callback")],
                    fields: { original: "okhttp3.Callback" },
                    methods: {
                        onFailure: function(call, e) {
                            this.original.value.onFailure(call, e);
                        },
                        onResponse: function(call, response) {
                            try {
                                console.log("\n⬅️ [OkHttp-Res] " + response.code() + " " + response.request().url());
                                // We can peek the body without consuming it using preview techniques or just headers
                                // Body is a stream, be careful not to consume it!
                                // For now, just headers and code is good proof.
                            } catch(e) {}
                            this.original.value.onResponse(call, response);
                        }
                    }
                });
                
                var wrapped = MyCallback.$new();
                wrapped.original.value = cb;
                return this.enqueue(wrapped);
                
            } catch(e) { 
                console.log("[-] OkHttp Hook Error: " + e); 
                return this.enqueue(cb);
            }
        }
        
        function logHeaders(headers) {
            if (!headers) return;
            var count = headers.size();
            for(var i=0; i<count; i++) {
                console.log("   " + headers.name(i) + ": " + headers.value(i));
            }
        }

        console.log("[+] OkHttp Java Hooks Active");
    } catch(e) { 
        console.log("[-] OkHttp Not Found/Error (Standard Obfuscation?): " + e);
        // Fallback: Try to find RealCall by methods if obfuscated (TODO)
    }


    // ====================================================================
    // [PART 5] SPECIFIC CONCRYPT NATIVE HOOK (From your list)
    // ====================================================================
    // ====================================================================
    // [PART 5] SPECIFIC CONCRYPT NATIVE HOOK (From your list)
    // ====================================================================
    setTimeout(function() {
        var specificLibPath = "/apex/com.android.conscrypt/lib64/libssl.so";
        var mod = null;
        
        // Manual find by path
        var modules = Process.enumerateModules();
        for (var i=0; i<modules.length; i++) {
            if (modules[i].path === specificLibPath) {
                mod = modules[i];
                break;
            }
        }

        if (mod) {
            console.log("[+] TARGETING SPECIFIC LIB: " + mod.name + " (" + mod.base + ")");
            // Use static Module.findExportByName with the module name found
            var sslWrite = Module.findExportByName(mod.name, "SSL_write");
            
            if (sslWrite) {
                 Interceptor.attach(sslWrite, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0) {
                                var buf = args[1].readByteArray(len);
                                var str = "";
                                var u8 = new Uint8Array(buf);
                                for(var i=0; i<Math.min(len, 4096); i++) {
                                    var c = u8[i];
                                    if((c>=32&&c<=126)||c==10||c==13) str+=String.fromCharCode(c);
                                    else str+=".";
                                }
                                if (str.match(/^(GET|POST|PUT|DELETE|HEAD) /)) {
                                    console.log("\n🎯 [CONCRYPT-REQ] \n" + str);
                                }
                            }
                        } catch(e) {}
                    }
                 });
                 console.log("[+] Specific SSL_write hooked.");
            } else {
                console.log("[-] SSL_write export not found in " + mod.name);
            }
        } else {
            console.log("[-] Specific lib path not found loaded: " + specificLibPath);
        }
    }, 1500);

});