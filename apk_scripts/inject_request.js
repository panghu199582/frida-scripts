Java.perform(function() {
    console.log("[*] Starting request interception script...");

    // 拦截 OkHttp 请求
    function hookOkHttp() {
        try {
            console.log("[*] Attempting to hook OkHttp...");
            
            // 检查类是否存在
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            if (!OkHttpClient) {
                console.log("[-] OkHttpClient class not found");
                return;
            }
            console.log("[+] Found OkHttpClient class");

            // 检查方法是否存在
            if (!OkHttpClient.newCall) {
                console.log("[-] newCall method not found");
                return;
            }
            console.log("[+] Found newCall method");

            OkHttpClient.newCall.implementation = function(request) {
                try {
                    console.log("[+] Intercepted OkHttpClient.newCall");
                    if (!request) {
                        console.log("[-] Request object is null");
                        return this.newCall(request);
                    }

                    console.log("[*] Request URL: " + request.url().toString());
                    console.log("[*] Request Method: " + request.method());
                    
                    // 获取请求头
                    var headers = request.headers();
                    if (headers) {
                        var headerNames = headers.names();
                        console.log("[*] Request Headers:");
                        for (var i = 0; i < headerNames.size(); i++) {
                            var name = headerNames.get(i);
                            console.log("    " + name + ": " + headers.get(name));
                        }
                    } else {
                        console.log("[-] Headers object is null");
                    }

                    // 获取请求体
                    var body = request.body();
                    if (body) {
                        console.log("[*] Request Body exists");
                        // 尝试读取请求体内容
                        try {
                            var bodyString = body.toString();
                            console.log("[*] Request Body: " + bodyString);
                        } catch(e) {
                            console.log("[-] Failed to read request body: " + e);
                        }
                    }

                    return this.newCall(request);
                } catch(e) {
                    console.log("[-] Error in newCall hook: " + e);
                    return this.newCall(request);
                }
            };
            console.log("[+] Successfully hooked OkHttpClient.newCall");
        } catch(e) {
            console.log("[-] Failed to hook OkHttpClient: " + e);
            console.log("[-] Stack trace: " + e.stack);
        }
    }

    // 拦截 HttpURLConnection
    function hookHttpURLConnection() {
        try {
            console.log("[*] Attempting to hook HttpURLConnection...");
            
            var URL = Java.use('java.net.URL');
            if (!URL) {
                console.log("[-] URL class not found");
                return;
            }
            console.log("[+] Found URL class");

            URL.openConnection.overload().implementation = function() {
                try {
                    console.log("[+] Intercepted URL.openConnection");
                    console.log("[*] URL: " + this.toString());
                    
                    var connection = this.openConnection();
                    if (connection) {
                        console.log("[*] Connection type: " + connection.getClass().getName());
                    }
                    
                    return connection;
                } catch(e) {
                    console.log("[-] Error in openConnection hook: " + e);
                    return this.openConnection();
                }
            };
            console.log("[+] Successfully hooked URL.openConnection");
        } catch(e) {
            console.log("[-] Failed to hook HttpURLConnection: " + e);
            console.log("[-] Stack trace: " + e.stack);
        }
    }

    // 拦截 Socket 连接
    function hookSocket() {
        try {
            console.log("[*] Attempting to hook socket...");
            
            var connectPtr = Module.findExportByName(null, 'connect');
            if (!connectPtr) {
                console.log("[-] connect function not found");
                return;
            }
            console.log("[+] Found connect function at: " + connectPtr);

            Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    try {
                        console.log("[+] Intercepted socket connect");
                        var sockAddr = args[1];
                        if (sockAddr) {
                            var port = Memory.readU16LE(sockAddr.add(2));
                            var addr = Memory.readU32LE(sockAddr.add(4));
                            console.log("[*] Connecting to: " + 
                                ((addr >> 24) & 0xFF) + "." +
                                ((addr >> 16) & 0xFF) + "." +
                                ((addr >> 8) & 0xFF) + "." +
                                (addr & 0xFF) + ":" + port);
                        } else {
                            console.log("[-] sockAddr is null");
                        }
                    } catch(e) {
                        console.log("[-] Error in socket connect hook: " + e);
                    }
                }
            });
            console.log("[+] Successfully hooked socket connect");
        } catch(e) {
            console.log("[-] Failed to hook socket: " + e);
            console.log("[-] Stack trace: " + e.stack);
        }
    }

    // 拦截 SSL/TLS 通信
    function hookSSL() {
        try {
            console.log("[*] Attempting to hook SSL...");
            
            // 检查 SSL_write
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (!sslWritePtr) {
                console.log("[-] SSL_write function not found");
            } else {
                console.log("[+] Found SSL_write at: " + sslWritePtr);
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            console.log("[+] Intercepted SSL_write");
                            var len = args[2].toInt32();
                            if (len > 0) {
                                var data = Memory.readByteArray(args[1], len);
                                console.log("[*] SSL Data (hex): " + bytes2hex(data));
                            }
                        } catch(e) {
                            console.log("[-] Error in SSL_write hook: " + e);
                        }
                    }
                });
            }

            // 检查 SSL_read
            var sslReadPtr = Module.findExportByName(null, 'SSL_read');
            if (!sslReadPtr) {
                console.log("[-] SSL_read function not found");
            } else {
                console.log("[+] Found SSL_read at: " + sslReadPtr);
                Interceptor.attach(sslReadPtr, {
                    onEnter: function(args) {
                        console.log("[+] Intercepted SSL_read");
                    },
                    onLeave: function(retval) {
                        try {
                            var len = retval.toInt32();
                            if (len > 0) {
                                var data = Memory.readByteArray(args[1], len);
                                console.log("[*] SSL Response (hex): " + bytes2hex(data));
                            }
                        } catch(e) {
                            console.log("[-] Error in SSL_read hook: " + e);
                        }
                    }
                });
            }
            console.log("[+] SSL hook setup completed");
        } catch(e) {
            console.log("[-] Failed to hook SSL: " + e);
            console.log("[-] Stack trace: " + e.stack);
        }
    }

    // 工具函数：将字节数组转换为十六进制字符串
    function bytes2hex(array) {
        var result = '';
        for (var i = 0; i < array.length; ++i) {
            result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
        }
        return result;
    }

    // 主函数
    function main() {
        console.log("[*] Starting request interception...");
        console.log("[*] Process ID: " + Process.id);
        console.log("[*] Process name: " + Process.getCurrentProcessName());
        
        // 列出已加载的模块
        console.log("[*] Loaded modules:");
        Process.enumerateModules().forEach(function(module) {
            console.log("    " + module.name + " at " + module.base);
        });

        hookOkHttp();
        hookHttpURLConnection();
        hookSocket();
        hookSSL();
        console.log("[+] Request interception setup completed");
    }

    // 执行主函数
    main();
}); 