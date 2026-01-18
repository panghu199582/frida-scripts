
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 追踪银行列表加载类 f.l.a.m.n0.d ...");

    function inspect(obj) {
        if (!obj) return "null";
        try {
            return obj.toString();
        } catch(e) { return "[Object]"; }
    }

    // Helper to trace a specific class
    function traceClass(className) {
        try {
            var Clazz = Java.use(className);
            var methods = Clazz.class.getDeclaredMethods();
            
            methods.forEach(function(method) {
                var methodName = method.getName();
                var overloads = Clazz[methodName].overloads;
                
                overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        console.log("\n[+] 调用 " + className + "." + methodName + "()");
                        for (var i = 0; i < arguments.length; i++) {
                            console.log("    Arg[" + i + "]: " + inspect(arguments[i]));
                        }
                        
                        var ret = this[methodName].apply(this, arguments);
                        
                        console.log("    Ret: " + inspect(ret));
                        // If return is a long string (JSON?), print it partially
                        if (ret && ret.toString().length > 100) {
                             console.log("    Ret(Cut): " + ret.toString().substring(0, 150) + "...");
                        }
                        
                        return ret;
                    }
                });
            });
            console.log("[*] Hooked " + className);
        } catch(e) {
            console.log("[-] Failed to hook " + className + ": " + e);
        }
    }

    // Trace the class identified in the stack trace
    traceClass("f.l.a.m.n0.d");
    
    // Trace the caller class just in case
    traceClass("f.l.a.m.n0.c");

});
