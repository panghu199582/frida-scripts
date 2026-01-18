// 添加一个全局的日志函数
function log(message) {
    try {
        console.log("[JNI_DEBUG] " + message);
    } catch(e) {
        console.log("[JNI_ERROR] Failed to log: " + e);
    }
}

// 在脚本开始时输出标记
log("=== JNI Hook Script Started ===");

// 要监控的 so 文件列表
var targetLibs = [
    "libTMXDeviceSecurityHealth-7.2-32-jni.so",
    "libTMXProfiling-7.2-32-jni.so",
    "libTransform.so",
    "libbarhopper_v2.so",
    "libcharting.so",
    "libcore.so",
    "libdata.so",
    "libdrawing.so",
    "libface_detector_v2_jni.so",
    "libfhcwtvqmy.so",
    "libtensorflowlite_jni.so",
    "libucs-credential.so",
    "libwb-native-lib.so"
];

// 添加错误处理
try {
    // Hook dlopen
    try {
        var dlopen = Module.findExportByName(null, "dlopen");
        if (dlopen) {
            log("Found dlopen at: " + dlopen);
            Interceptor.attach(dlopen, {
                onEnter: function(args) {
                    var path = args[0].readCString();
                    if (path) {
                        var filename = path.split("/").pop();
                        if (targetLibs.includes(filename)) {
                            log("=== Loading " + filename + " via dlopen ===");
                            log("Full path: " + path);
                            log("Call stack:");
                            log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        }
                    }
                }
            });
        } else {
            log("dlopen not found");
        }
    } catch(e) {
        log("dlopen hook failed: " + e);
    }

    // Hook dlsym
    try {
        var dlsym = Module.findExportByName(null, "dlsym");
        if (dlsym) {
            log("Found dlsym at: " + dlsym);
            Interceptor.attach(dlsym, {
                onEnter: function(args) {
                    var handle = args[0];
                    var symbol = args[1].readCString();
                    if (symbol) {
                        // 只记录与目标库相关的符号查找
                        var module = Process.findModuleByAddress(handle);
                        if (module && targetLibs.includes(module.name)) {
                            log("=== dlsym called for " + module.name + " ===");
                            log("Symbol: " + symbol);
                            log("Handle: " + handle);
                            log("Call stack:");
                            log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        }
                    }
                }
            });
        } else {
            log("dlsym not found");
        }
    } catch(e) {
        log("dlsym hook failed: " + e);
    }

    Java.perform(function() {
        log("Script started");

        // Hook System.loadLibrary
        try {
            var System = Java.use("java.lang.System");
            System.loadLibrary.implementation = function(libname) {
                if (targetLibs.includes(libname + ".so")) {
                    log("=== Loading " + libname + " via System.loadLibrary ===");
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

        // Hook Runtime.loadLibrary
        try {
            var Runtime = Java.use("java.lang.Runtime");
            // Hook 第一个重载方法 (String)
            Runtime.loadLibrary.overload('java.lang.String').implementation = function(libname) {
                if (targetLibs.includes(libname + ".so")) {
                    log("=== Loading " + libname + " via Runtime.loadLibrary(String) ===");
                    log("Call stack:");
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                }
                return this.loadLibrary(libname);
            };

            // Hook 第二个重载方法 (String, ClassLoader)
            Runtime.loadLibrary.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(libname, loader) {
                if (targetLibs.includes(libname + ".so")) {
                    log("=== Loading " + libname + " via Runtime.loadLibrary(String, ClassLoader) ===");
                    log("ClassLoader: " + loader);
                    log("Call stack:");
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                }
                return this.loadLibrary(libname, loader);
            };
        } catch(e) {
            log("Runtime.loadLibrary hook failed: " + e);
        }

        // Hook JNI 函数
        try {
            // 获取所有已加载的模块
            var modules = Process.enumerateModules();
            for (var i = 0; i < modules.length; i++) {
                var module = modules[i];
                // 只监控目标 so 文件
                if (targetLibs.includes(module.name)) {
                    log("Found module: " + module.name + " at " + module.path);
                    
                    // 监控 JNI_OnLoad
                    try {
                        var jniOnLoad = Module.findExportByName(module.name, "JNI_OnLoad");
                        if (jniOnLoad) {
                            log("Found JNI_OnLoad in " + module.name);
                            Interceptor.attach(jniOnLoad, {
                                onEnter: function(args) {
                                    log("=== JNI_OnLoad called in " + module.name + " ===");
                                    log("JavaVM: " + args[0]);
                                },
                                onLeave: function(retval) {
                                    log("JNI_OnLoad returned: " + retval);
                                }
                            });
                        }
                    } catch(e) {
                        log("Failed to hook JNI_OnLoad in " + module.name + ": " + e);
                    }
                    
                    // 监控导出函数
                    var exports = Module.enumerateExports(module.name);
                    for (var j = 0; j < exports.length; j++) {
                        var exp = exports[j];
                        // 只监控特定的 JNI 函数
                        // if (exp.name.startsWith("Java_") && 
                        //     (exp.name.includes("TMX") || 
                        //      exp.name.includes("security") || 
                        //      exp.name.includes("credential"))) {
                            
                        log("Found target JNI export: " + exp.name);
                        try {
                            Interceptor.attach(exp.address, {
                                onEnter: function(args) {
                                    log("=== Called: " + exp.name + " ===");
                                    // 打印参数
                                    for (var k = 0; k < 4; k++) {
                                        if (args[k]) {
                                            try {
                                                var str = args[k].readCString();
                                                if (str) {
                                                    log("  arg[" + k + "]: " + str);
                                                } else {
                                                    log("  arg[" + k + "]: " + args[k]);
                                                }
                                            } catch(e) {
                                                log("  arg[" + k + "]: " + args[k]);
                                            }
                                        }
                                    }
                                },
                                onLeave: function(retval) {
                                    log("=== Returned: " + exp.name + " ===");
                                    if (retval) {
                                        try {
                                            var str = retval.readCString();
                                            if (str) {
                                                log("  return: " + str);
                                            } else {
                                                log("  return: " + retval);
                                            }
                                        } catch(e) {
                                            log("  return: " + retval);
                                        }
                                    } else {
                                        log("  return: null");
                                    }
                                }
                            });
                        } catch(e) {
                            log("Failed to attach to " + exp.name + ": " + e);
                        }
                        // }
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