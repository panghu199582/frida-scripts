// iOS 网络请求拦截脚本

function log(message) {
    console.log("\x1b[33m[*] " + message + "\x1b[0m");
}

function logError(message) {
    console.log("\x1b[31m[-] " + message + "\x1b[0m");
}

function logSuccess(message) {
    console.log("\x1b[32m[+] " + message + "\x1b[0m");
}

function formatData(data, length) {
    try {
        var result = Memory.readUtf8String(data, length);
        if (result === null) {
            var bytes = Memory.readByteArray(data, length);
            if (bytes) {
                var uint8Array = new Uint8Array(bytes);
                result = Array.from(uint8Array).map(b => b.toString(16).padStart(2, '0')).join(' ');
            }
        }
        return result || "<无法读取数据>";
    } catch(e) {
        return "<读取数据时出错: " + e + ">";
    }
}

function shouldInterceptUrl(url) {
    return url && url.toString().includes('mapi.vib.com.vn');
}

if (ObjC.available) {
    log("开始抓包...");

    try {
        // 拦截 NSURLSession
        try {
            var URLSessionClass = ObjC.classes.NSURLSession;
            if (URLSessionClass) {
                var dataTaskMethod = URLSessionClass['- dataTaskWithRequest:completionHandler:'];
                if (dataTaskMethod) {
                    Interceptor.attach(dataTaskMethod.implementation, {
                        onEnter: function(args) {
                            try {
                                var request = new ObjC.Object(args[2]);
                                var url = request.URL();
                                
                                // 只处理目标域名的请求
                                if (!shouldInterceptUrl(url.absoluteString())) {
                                    return;
                                }
                                
                                logSuccess("\n=== NSURLSession 请求 ===");
                                log("URL: " + url.absoluteString());
                                
                                // 方法
                                var method = request.HTTPMethod();
                                if (method) {
                                    log("方法: " + method);
                                }
                                
                                // 请求头
                                var headers = request.allHTTPHeaderFields();
                                if (headers) {
                                    log("\n请求头:");
                                    var keys = headers.allKeys();
                                    var count = keys.count();
                                    for (var i = 0; i < count; i++) {
                                        var key = keys.objectAtIndex_(i);
                                        if (key) {
                                            var value = headers.objectForKey_(key);
                                            if (value) {
                                                log(key + ": " + value);
                                            }
                                        }
                                    }
                                }
                                
                                // 请求体
                                var body = request.HTTPBody();
                                if (body) {
                                    log("\n请求体:");
                                    var NSString = ObjC.classes.NSString;
                                    var bodyStr = NSString.alloc().initWithData_encoding_(body, 4);
                                    if (bodyStr) {
                                        log(bodyStr.toString());
                                    }
                                }
                                
                                logSuccess("===================\n");
                            } catch (e) {
                                logError("处理NSURLSession请求时出错: " + e);
                            }
                        }
                    });
                    logSuccess("已hook NSURLSession");
                }
            }
        } catch(e) {
            logError("Hook NSURLSession失败: " + e);
        }

        // 拦截 SSL/TLS 相关函数
        var targetFunctions = [
            'SSL_write',
            'SSL_read'
        ];

        targetFunctions.forEach(function(funcName) {
            var funcPtr = Module.findExportByName(null, funcName);
            if (funcPtr) {
                Interceptor.attach(funcPtr, {
                    onEnter: function(args) {
                        this.funcName = funcName;
                        this.buf = args[1];
                        this.len = parseInt(args[2]);
                    },
                    onLeave: function(retval) {
                        try {
                            var len = this.funcName.includes('read') ? parseInt(retval) : this.len;
                            if (len > 0) {
                                var data = formatData(this.buf, len);
                                // 只处理包含目标域名的请求
                                if (data.includes('mapi.vib.com.vn') &&
                                    (data.includes('HTTP/') || 
                                     data.includes('POST') || 
                                     data.includes('GET'))) {
                                    logSuccess("\n=== " + this.funcName + " ===");
                                    log("长度: " + len);
                                    log("数据:\n" + data);
                                    logSuccess("===================\n");
                                }
                            }
                        } catch(e) {
                            logError(this.funcName + " 处理数据时出错: " + e);
                        }
                    }
                });
                logSuccess("已hook " + funcName);
            }
        });

        // 拦截 CFNetwork
        var cfnetwork = Module.findBaseAddress('CFNetwork');
        if (cfnetwork) {
            ['SSLWrite', 'SSLRead'].forEach(function(name) {
                var addr = Module.findExportByName('CFNetwork', name);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            this.funcName = name;
                            this.buf = args[1];
                            this.len = parseInt(args[2]);
                        },
                        onLeave: function(retval) {
                            try {
                                var len = this.funcName.includes('Read') ? parseInt(retval) : this.len;
                                if (len > 0) {
                                    var data = formatData(this.buf, len);
                                    // 只处理包含目标域名的请求
                                    if (data.includes('mapi.vib.com.vn') &&
                                        (data.includes('HTTP/') || 
                                         data.includes('POST') || 
                                         data.includes('GET'))) {
                                        logSuccess("\n=== CFNetwork." + this.funcName + " ===");
                                        log("长度: " + len);
                                        log("数据:\n" + data);
                                        logSuccess("===================\n");
                                    }
                                }
                            } catch(e) {
                                logError("CFNetwork." + this.funcName + " 处理数据时出错: " + e);
                            }
                        }
                    });
                    logSuccess("已hook CFNetwork." + name);
                }
            });
        }

        log("抓包已启动，等待请求...");

    } catch(e) {
        logError("设置拦截器失败: " + e.stack || e);
    }
} else {
    logError("Objective-C Runtime不可用");
}