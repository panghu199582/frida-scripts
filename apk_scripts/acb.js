// Bypass DexProtector JNI Version check
function bypass_jni_check() {
    try {
        console.log("[+] Setting up JNI bypass hooks...");
        
        // Use Process.findExportByName to avoid "Module.findExportByName is not a function" error
        var dlopen = Process.findExportByName(null, "dlopen");
        var android_dlopen_ext = Process.findExportByName(null, "android_dlopen_ext");

        function hook_jni(name) {
            if (name && name.indexOf("dexprotector") !== -1) {
                console.log("[!] DexProtector/Lib loaded: " + name);
                
                // Retry finding the module with a small delay or check immediately
                var simpleName = name.split("/").pop();
                var mod = Process.findModuleByName(name) || Process.findModuleByName(simpleName);
                
                if (mod) {
                    console.log("[+] Module found: " + mod.name + " Base: " + mod.base);
                    var jniOnLoad = mod.findExportByName("JNI_OnLoad");
                    if (jniOnLoad) {
                        console.log("[+] JNI_OnLoad found at: " + jniOnLoad);
                        Interceptor.attach(jniOnLoad, {
                            onLeave: function(retval) {
                                console.log("[*] JNI_OnLoad returning: " + retval);
                                // Valid JNI version 1.6 is 0x10006
                                retval.replace(0x10006);
                                console.log("[+] Force substituted JNI version to 0x10006");
                            }
                        });
                    } else {
                        console.log("[-] JNI_OnLoad export NOT found in " + mod.name);
                        // Fallback: If symbol is stripped, we might need to scan/guess. 
                        // But JNI_OnLoad is usually exported.
                    }
                } else {
                    console.log("[-] Frida could not find module object for " + name);
                }
            }
        }

        if (android_dlopen_ext) {
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function(args) {
                    try {
                        this.name = args[0].readCString();
                    } catch(e) { this.name = null; }
                },
                onLeave: function(retval) {
                    if (this.name) hook_jni(this.name);
                }
            });
        }

        if (dlopen) {
            Interceptor.attach(dlopen, {
                onEnter: function(args) {
                    try {
                        this.name = args[0].readCString();
                    } catch(e) { this.name = null; }
                },
                onLeave: function(retval) {
                     if (this.name) hook_jni(this.name);
                }
            });
        }
    } catch(e) {
        console.log("[!] Error in bypass_jni_check: " + e);
    }
}
bypass_jni_check();

// Java hook: must run inside Java.perform
function hook_java_string() {
    try {
        console.log("Installing Java String hooks (Comprehensive)...");
        var StringClass = Java.use("java.lang.String");
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");

        // Helper to check and log
        function checkAndLog(str, source) {
            // Filter: 6 digits (OTP)
            if (str && str.length === 6 && /^\d+$/.test(str)) {
                console.log("\n[!] Possible OTP Found: " + str);
                console.log("    Source: " + source);
                try {
                    var stack = Log.getStackTraceString(Exception.$new());
                    console.log("    Stack Trace:\n" + stack);
                } catch(e) {
                    console.log("    Failed to get stack trace: " + e);
                }
            }
        }

        // 1. String(byte[], String charset)
        try {
            StringClass.$init.overload('[B', 'java.lang.String').implementation = function (bytes, charset) {
                var result = this.$init(bytes, charset);
                checkAndLog(result, "byte[], charset");
                return result;
            };
        } catch(e) {}

        // 2. String(byte[])
        try {
            StringClass.$init.overload('[B').implementation = function (bytes) {
                var result = this.$init(bytes);
                checkAndLog(result, "byte[]");
                return result;
            };
        } catch(e) {}

        // 3. String(char[])
        try {
            StringClass.$init.overload('[C').implementation = function (chars) {
                var result = this.$init(chars);
                checkAndLog(result, "char[]");
                return result;
            };
        } catch(e) {}
        
        // 4. String(String) - Copy constructor
        try {
            StringClass.$init.overload('java.lang.String').implementation = function (original) {
                var result = this.$init(original);
                // checkAndLog(result, "String copy"); 
                return result;
            };
        } catch(e) {}

        // 5. CRITICAL: String(char[], int, int) - Used by StringBuilder.toString()
        try {
            StringClass.$init.overload('[C', 'int', 'int').implementation = function (chars, offset, count) {
                var result = this.$init(chars, offset, count);
                checkAndLog(result, "char[], int, int (StringBuilder?)");
                return result;
            };
        } catch(e) {}

        // 6. String(byte[], int, int, String charset)
        try {
            StringClass.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (bytes, offset, length, charset) {
                var result = this.$init(bytes, offset, length, charset);
                checkAndLog(result, "byte[], int, int, charset");
                return result;
            };
        } catch(e) {}
        
        // 7. Monitor Integer.toString() as well
        try {
            var Integer = Java.use("java.lang.Integer");
            Integer.toString.overload('int').implementation = function(i) {
                var result = this.toString(i);
                if (result.length === 6) { 
                     checkAndLog(result, "Integer.toString");
                }
                return result;
            };
        } catch(e) {}

        console.log("Java String hooks installed (Expanded coverage).");
    } catch(e) {
        console.log("Error in hook_java_string: " + e);
    }

    
}

function hook_hmac_final() {
    // 使用 Process 代替 Module 查找，更健壮
    const libcrypto = Process.findModuleByName("libcrypto.so") || Process.findModuleByName("libboringssl.so");

    if (libcrypto) {
        const hmacAddr = libcrypto.findExportByName("HMAC");
        if (hmacAddr) {
            Interceptor.attach(hmacAddr, {
                onEnter: function (args) {
                    console.log("[*] HMAC 入口被触发！来自模块: " + Process.findModuleByAddress(this.returnAddress).name);
                    
                    // 打印 Data 长度
                    const dataLen = args[4].toInt32();
                    console.log("[*] Data 长度: " + dataLen);
                    
                    // 打印 Data 的十六进制内容（这就是你计算失败的真相）
                    console.log("[*] Data (HexDump):\n" + hexdump(args[3], { length: dataLen, ansi: true }));
                }
            });
            console.log("[+] 成功 Hook HMAC 函数");
        }
    } else {
        console.log("[-] 尚未发现 libcrypto.so，请先操作 App 触发加密动作");
    }
}

// 建议设置一个延迟或者在 Java.perform 中调用
setTimeout(hook_hmac_final, 1000);

// Native hook: can run immediately
function hook_native_crypto() {
    try {
        console.log("Installing Native Crypto hooks...");
        
        // Use Process.findExportByName as a safer alternative to Module.findExportByName
        var memcpyAddr = Process.findExportByName(null, "memcpy");
        if (memcpyAddr) {
            Interceptor.attach(memcpyAddr, {
                onEnter: function (args) {
                    this.dest = args[0];
                    this.len = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (this.len === 6) { 
                        try {
                            var content = this.dest.readUtf8String(6);
                            if (/^\d{6}$/.test(content)) {
                                console.log("[Native memcpy] 6-digit string: " + content);
                            }
                        } catch (e) {}
                    }
                }
            });
            console.log("memcpy hook installed.");
        } else {
            console.log("memcpy export not found.");
        }

        var hmacPtr = Process.findExportByName(null, "HMAC"); 
        if (hmacPtr) {
            Interceptor.attach(hmacPtr, {
                onEnter: function (args) {}
            });
            console.log("HMAC hook installed.");
        }
    } catch(e) {
        console.log("Error in hook_native_crypto: " + e);
    }
}

// Hook for OCRA generation
function hook_ocra() {
    Java.perform(function() {
        try {
            console.log("Attempting to hook vn.com.pvcombank.RNOcra.OCRAModule...");
            var OCRAModule = Java.use("vn.com.pvcombank.RNOcra.OCRAModule");

            // Hook generateOCRA
            var overloads = OCRAModule.generateOCRA.overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("\n[OCRA] generateOCRA called!");
                    for (var i = 0; i < arguments.length; i++) {
                        console.log("  Arg[" + i + "]: " + arguments[i]);
                    }
                    var result = this.generateOCRA.apply(this, arguments);
                    console.log("  Result: " + result);
                    return result;
                };
            });
            console.log("Hooked generateOCRA (Java internal)");

            // Hook OCRA_generateOCRA (Bridge method likely)
            var overloads2 = OCRAModule.OCRA_generateOCRA.overloads;
            overloads2.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("\n[OCRA] OCRA_generateOCRA called (Bridge)!");
                    for (var i = 0; i < arguments.length; i++) {
                        console.log("  Arg[" + i + "]: " + arguments[i]);
                    }
                    var result = this.OCRA_generateOCRA.apply(this, arguments);
                    console.log("  Result: " + result);
                    return result;
                };
            });
             console.log("Hooked OCRA_generateOCRA (Bridge)");

        } catch(e) {
            console.log("Error hooking OCRAModule: " + e);
        }
    });
}

// Call hooks
hook_native_crypto();
Java.perform(hook_java_string);
hook_ocra();



// 辅助函数：打印调用栈
function showStackTrace() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

const Color = { RESET: "\x1b[0m", GREEN: "\x1b[32m", YELLOW: "\x1b[33m", BLUE: "\x1b[34m" };


// 添加一个全局的日志函数
function log(message) {
    try {
        console.log("[BBL_DEBUG] " + message);
        Java.perform(function() {
            var Log = Java.use("android.util.Log");
            Log.d("BBL_DEBUG", message);
        });
    } catch(e) {
        console.log("[BBL_ERROR] Failed to log: " + e);
    }
}

// 在脚本开始时输出标记
log("=== BBL JSHook Script Started ===");
// Java.perform(hook_crypto_outputs);
// 添加错误处理
try {
    // Call hooks
    hook_native_crypto();
    Java.perform(hook_java_string);
    Java.perform(function() {
        
        log("Script started");
        var Buffer = Java.use('okio.Buffer');
        // 检查进程名
        var Process = Java.use("android.os.Process");
        var currentPid = Process.myPid();
        log("Current process ID: " + currentPid);

        // 1. OkHttp
        // Global set to track hooked Call classes to avoid re-hooking
        var hookedCallClasses = new Set();
        
        // Helper to safe-read body from Buffer/Source
        function readSource(source, byteCount) {
             try {
                if (!source) return "null source";
                // Debug class name
                // log("Source class: " + source.getClass().getName());

                var BufferedSource = Java.use("okio.BufferedSource");
                var bufferedSource = Java.cast(source, BufferedSource);
                
                // Try modern okio peek()
                try {
                    var peekSource = bufferedSource.peek();
                    // Read up to byteCount bytes as ByteString
                    var byteString = peekSource.readByteString(byteCount);
                    return byteString.utf8();
                } catch(peekErr) {
                    // log("peek() failed (maybe old okio?), trying request+buffer: " + peekErr);
                    
                    // Fallback
                    // Ensure byteCount is a long
                    // bufferedSource.request(byteCount); // This expects long
                    
                    // Trying to just get buffer()
                    var buffer = bufferedSource.buffer(); // Returns Buffer
                    // Clone it safely?
                    var clone = buffer.clone();
                    // Read from clone. If buffer is huge, this might be partial?
                    // clone is a deep copy of the buffer content
                    return clone.readUtf8();
                }
             } catch(e) {
                 return "Error reading source: " + e;
             }
        }

        // Helper to inspect Response object
        function inspectResponse(response) {
            // try {
                if (!response) return;
                var request = response.request();
                var url = request.url().toString();
                
                if (url.indexOf("trace-pvconnect.pvcombank.com.vn/v1/traces") !== -1) return;

                log("========================================");
                log("[Response] " + response.code() + " " + url);
                console.log(response)
                var body = response.body();
                console.log("response body", body);
                if (body) {
                //    try {
                       // ResponseBody does not have writeTo(), only RequestBody does.
                       // We must use source() to read ResponseBody.
                       var source = body.source(); // returns BufferedSource
                       
                       // Explicit cast to ensure we call the interface method correctly
                       var BufferedSource = Java.use("okio.BufferedSource");
                       var castSource = Java.cast(source, BufferedSource);

                       // Buffer the entire body (limit to 10MB to be safe)
                       // You must pass a number (Frida handles long conversion)
                       castSource.request(10 * 1024 * 1024); 
                       
                       var buffer = castSource.buffer(); // returns okio.Buffer
                       
                       // Clone the buffer so we don't consume the original response
                       var OkioBuffer = Java.use("okio.Buffer");
                       var castBuffer = Java.cast(buffer, OkioBuffer);
                       var clone = castBuffer.clone();
                       
                       // IMPORTANT: clone() returns java.lang.Object (or standard clone return), 
                       // we must cast the CLONE itself to use okio methods on it
                       var castClone = Java.cast(clone, OkioBuffer);
                       
                       var bodyString = castClone.readUtf8();
                       log("[Response Body]\n" + bodyString);
                       log("[Response Body]\n" + bodyString);
                //    } catch(e) {
                //        log("[Response Body Error] " + e);
                //    }
                }
            // } catch (e) {
            //     log("Error inspecting response: " + e);
            // }
        }

        // 1. OkHttp Dynamic Hooking
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var newCall = OkHttpClient.newCall.overload('okhttp3.Request');
            
            newCall.implementation = function(request) {
                try {
                     var url = request.url().toString();
                     // Filter
                     if (url.indexOf("trace-pvconnect.pvcombank.com.vn/v1/traces") === -1) {
                         log("========================================");
                         log("[Request] " + request.method() + " " + url);
                         
                         // 1. Log Headers
                         var headers = request.headers();
                         if (headers && headers.size() > 0) {
                             // Using standard iterator or checking size
                             for (var i = 0; i < headers.size(); i++) {
                                 log("  " + headers.name(i) + ": " + headers.value(i));
                             }
                         }

                         // 2. Log Body
                         var body = request.body();
                         // Log request body cautiously
                         try {
                             if (body) {
                                 var buffer = Java.use("okio.Buffer").$new();
                                 body.writeTo(buffer);
                                 
                                 var contentType = request.header("Content-Type");
                                 if (contentType && (contentType.indexOf("image") !== -1 || contentType.indexOf("octet-stream") !== -1)) {
                                     // Binary/Image data: Print Hex Dump (first 64 bytes)
                                     var ByteString = Java.use("okio.ByteString");
                                     var hex = buffer.readByteString().hex();
                                     if (hex.length > 128) {
                                         log("[Request Body] (Binary/Image) Hex (Truncated):\n" + hex.substring(0, 128) + "...");
                                     } else {
                                         log("[Request Body] (Binary/Image) Hex:\n" + hex);
                                     }
                                 } else {
                                     // Text data
                                     var bodyStr = buffer.readUtf8();
                                     log("[Request Body]\n" + bodyStr);
                                 }
                             }
                         } catch(e) {
                             // ignore body error
                             log("Err log req body: " + e);
                         }
                         log("========================================");
                     }
                } catch(e) { log("Err log req: " + e); }

                var call = newCall.call(this, request);
                
                try {
                    var className = call.$className;
                    
                    if (className && !hookedCallClasses.has(className)) {
                        log("Hooking Call class: " + className);
                        hookedCallClasses.add(className);
                        
                        var CallImpl = Java.use(className);
                        
                        // Hook synchronous execute()
                        try {
                            var execute = CallImpl.execute.overload();
                            execute.implementation = function() {
                                var response = execute.call(this)
                                // inspectResponse(response);
                                log("get execute")
                                return response;
                            };
                            log("Hooked execute() on " + className);
                        } catch(e) { log("Failed hook execute: " + e); }

                        // Hook asynchronous enqueue()
                        try {
                            var enqueue = CallImpl.enqueue.overload('okhttp3.Callback');
                            
                            // Create a unique wrapper class for this Call implementation
                            var wrapperClassName = 'com.bbl.hook.CallbackWrapper_' + className.replace(/\./g, '_');
                            var WrapperClass;
                            try {
                                WrapperClass = Java.use(wrapperClassName);
                            } catch (e) {
                                WrapperClass = Java.registerClass({
                                    name: wrapperClassName,
                                    implements: [Java.use('okhttp3.Callback')],
                                    fields: { originalCallback: 'okhttp3.Callback' },
                                    methods: {
                                        onFailure: function(call, e) {
                                            if (this.originalCallback.value) this.originalCallback.value.onFailure(call, e);
                                        },
                                        onResponse: function(call, response) {
                                            inspectResponse(response);
                                            if (this.originalCallback.value) this.originalCallback.value.onResponse(call, response);
                                        }
                                    }
                                });
                            }

                            enqueue.implementation = function(callback) {
                                var myCallback = WrapperClass.$new();
                                myCallback.originalCallback.value = callback;
                                enqueue.call(this, myCallback);
                            };
                            log("Hooked enqueue() on " + className);
                        } catch(e) { log("Failed hook enqueue: " + e); }
                    }
                } catch(e) {
                    log("Dynamic hook error: " + e);
                }
                
                return call;
            };
            log("OkHttp dynamic (Request & Response) hooks installed");
        } catch(e) {
            log("OkHttp hook failed: " + e);
        }

     

    

        // 16. KeyStore Monitor
        try {
            var KeyStore = Java.use("java.security.KeyStore");
            
            // Hook load
            var load = KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter');
            load.implementation = function(param) {
                log("[KeyStore] loading...");
                return load.call(this, param);
            };

            // Hook getEntry
            var getEntry = KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter');
            getEntry.implementation = function(alias, param) {
                log("[KeyStore] getEntry: " + alias);
                return getEntry.call(this, alias, param);
            };

            // Hook getKey
            var getKey = KeyStore.getKey.overload('java.lang.String', '[C');
            getKey.implementation = function(alias, password) {
                log("[KeyStore] getKey: " + alias);
                return getKey.call(this, alias, password);
            };

            // Hook aliases
            var aliases = KeyStore.aliases.overload();
            aliases.implementation = function() {
                var result = aliases.call(this);
                // log("[KeyStore] aliases called");
                return result;
            };

            log("KeyStore hooks installed");
        } catch(e) {
            log("KeyStore hook failed: " + e);
        }

        // 心跳日志
        setInterval(function() {
            // log("Script is still running...");
        }, 5000);

        log("All hooks installed successfully");
    });
} catch(e) {
    log("Fatal error in script: " + e);
} 