function log(message) {
    console.log("\x1b[36m[*] " + message + "\x1b[0m");
}

function logError(message) {
    console.log("\x1b[31m[-] " + message + "\x1b[0m");
}

function logSuccess(message) {
    console.log("\x1b[32m[+] " + message + "\x1b[0m");
}

function logStack(context) {
    if (!context) {
        console.log("\x1b[33m[STACK] Stack trace not available\x1b[0m");
        return;
    }
    console.log("\x1b[33m[STACK] Current stack trace:\x1b[0m\n" + 
        Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");
}

const INTERESTING_HEADERS = [
    "authorization_app_key",
    "signature",
    "device_id",
    "unique_device_id"
];

function installHooks() {
    log("Installing hooks...");

    try {
        // 只监控请求头的设置
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        if (NSMutableURLRequest) {
            var setValueMethod = NSMutableURLRequest["- setValue:forHTTPHeaderField:"];
            if (setValueMethod && setValueMethod.implementation) {
                Interceptor.attach(setValueMethod.implementation, {
                    onEnter: function(args) {
                        try {
                            var value = new ObjC.Object(args[2]);
                            var field = new ObjC.Object(args[3]);
                            
                            if (INTERESTING_HEADERS.some(h => field.toString().includes(h))) {
                                logSuccess("Setting header");
                                log("Field: " + field);
                                log("Value: " + value);
                                logStack(this.context);
                            }
                        } catch(e) {
                            logError("Error in header hook: " + e);
                        }
                    }
                });
                logSuccess("Hooked NSMutableURLRequest setValue:forHTTPHeaderField:");
            }
        }

        // 监控 NSURLSession 的数据任务创建
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            var dataTaskMethod = NSURLSession["- dataTaskWithRequest:completionHandler:"];
            if (dataTaskMethod && dataTaskMethod.implementation) {
                Interceptor.attach(dataTaskMethod.implementation, {
                    onEnter: function(args) {
                        try {
                            var request = new ObjC.Object(args[2]);
                            var url = request.URL().absoluteString();
                            
                            if (url.toString().includes("mapi.vib.com.vn")) {
                                logSuccess("VIB API Request");
                                log("URL: " + url);
                                
                                // 获取所有请求头
                                var headers = request.allHTTPHeaderFields();
                                var keys = headers.allKeys();
                                var count = keys.count();
                                for (var i = 0; i < count; i++) {
                                    var key = keys.objectAtIndex_(i);
                                    var value = headers.objectForKey_(key);
                                    log(key + ": " + value);
                                }
                                
                                logStack(this.context);
                            }
                        } catch(e) {
                            logError("Error in session hook: " + e);
                        }
                    }
                });
                logSuccess("Hooked NSURLSession dataTaskWithRequest:");
            }
        }

        log("Hooks installed successfully");

    } catch(e) {
        logError("Failed to install hooks: " + e.stack || e);
    }
}

if (ObjC.available) {
    log("Starting request header tracer...");
    
    // 延迟安装 hooks，等待应用完全启动
    setTimeout(function() {
        log("Delayed hook installation starting...");
        installHooks();
    }, 2000);  // 延迟 2 秒
    
} else {
    logError("Objective-C Runtime is not available");
}