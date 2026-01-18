// 添加一个全局的日志函数
function log(message) {
    try {
        console.log("[TRANSFORM_DEBUG] " + message);
    } catch(e) {
        console.log("[TRANSFORM_ERROR] Failed to log: " + e);
    }
}

// 在脚本开始时输出标记
log("=== Transform Hook Script Started ===");

// 添加错误处理
try {
    Java.perform(function() {
        log("Script started");

        // Hook System.loadLibrary
        try {
            var System = Java.use("java.lang.System");
            System.loadLibrary.implementation = function(libname) {
                if (libname === "Transform") {
                    log("=== Loading libTransform.so ===");
                    log("Call stack:");
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                }
                return this.loadLibrary(libname);
            };
        } catch(e) {
            log("System.loadLibrary hook failed: " + e);
        }

        // Hook JNI 函数
        try {
            var libTransform = Module.findBaseAddress('libTransform.so');
            if (libTransform) {
                log("Found libTransform.so at: " + libTransform);
                
                // 只监控特定的导出函数
                var exports = Module.enumerateExports('libTransform.so');
                for (var i = 0; i < exports.length; i++) {
                    var exp = exports[i];
                    if (exp.name.includes("Java_") || exp.name.includes("transform")) {
                        log("Found target export: " + exp.name);
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                log("=== Called: " + exp.name);
                            },
                            onLeave: function(retval) {
                                log("=== Returned: " + exp.name);
                            }
                        });
                    }
                }
            }
        } catch(e) {
            log("JNI hook failed: " + e);
        }
        
        log("Hooks installed");
    });
} catch(e) {
    log("Fatal error: " + e);
} 