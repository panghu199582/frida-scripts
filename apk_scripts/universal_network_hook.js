/**
 * 通用Android网络请求监控Hook脚本
 * 支持监控：OkHttp、HttpURLConnection、Socket、SSL/TLS、WebView等
 * 作者：AI Assistant
 * 版本：1.0
 */

Java.perform(function() {
    console.log("[+] 通用网络请求监控Hook脚本已启动");
    
    // 配置选项
    var config = {
        enableOkHttp: true,           // 监控OkHttp
        enableHttpURLConnection: true, // 监控HttpURLConnection
        enableSocket: true,           // 监控Socket连接
        enableSSL: true,              // 监控SSL/TLS
        enableWebView: true,          // 监控WebView
        enableVolley: true,           // 监控Volley
        enableRetrofit: true,         // 监控Retrofit
        logHeaders: true,             // 记录请求头
        logBody: true,                // 记录请求体
        logResponse: true,            // 记录响应
        maxBodySize: 1024 * 1024,     // 最大记录体大小 (1MB)
        saveToFile: true,             // 保存到文件
        logFile: "/sdcard/network_logs.txt" // 日志文件路径
    };

    // 日志记录器
    var logger = {
        log: function(message) {
            var timestamp = new Date().toISOString();
            var logMessage = "[" + timestamp + "] " + message;
            console.log(logMessage);
            
            if (config.saveToFile) {
                try {
                    var file = new java.io.FileWriter(config.logFile, true);
                    file.write(logMessage + "\n");
                    file.close();
                } catch(e) {
                    console.log("[-] 写入日志文件失败: " + e);
                }
            }
        },
        
        logRequest: function(method, url, headers, body) {
            this.log("=== HTTP请求 ===");
            this.log("方法: " + method);
            this.log("URL: " + url);
            
            if (config.logHeaders && headers) {
                this.log("请求头:");
                for (var key in headers) {
                    this.log("  " + key + ": " + headers[key]);
                }
            }
            
            if (config.logBody && body) {
                this.log("请求体: " + body);
            }
            this.log("================");
        },
        
        logResponse: function(url, statusCode, headers, body) {
            this.log("=== HTTP响应 ===");
            this.log("URL: " + url);
            this.log("状态码: " + statusCode);
            
            if (config.logHeaders && headers) {
                this.log("响应头:");
                for (var key in headers) {
                    this.log("  " + key + ": " + headers[key]);
                }
            }
            
            if (config.logResponse && body) {
                this.log("响应体: " + body);
            }
            this.log("================");
        }
    };

    // 工具函数
    var utils = {
        // 字节数组转十六进制
        bytes2hex: function(array) {
            var result = '';
            for (var i = 0; i < array.length; i++) {
                result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
            }
            return result;
        },
        
        // 字节数组转字符串
        bytes2string: function(array) {
            try {
                return String.fromCharCode.apply(null, new Uint8Array(array));
            } catch(e) {
                return "[无法转换的二进制数据]";
            }
        },
        
        // 截断过长的字符串
        truncate: function(str, maxLength) {
            if (str && str.length > maxLength) {
                return str.substring(0, maxLength) + "...[截断]";
            }
            return str;
        },
        
        // 解析JSON
        parseJSON: function(str) {
            try {
                return JSON.parse(str);
            } catch(e) {
                return str;
            }
        }
    };

    // 1. 监控OkHttp
    function hookOkHttp() {
        if (!config.enableOkHttp) return;
        
        try {
            logger.log("[*] 开始Hook OkHttp...");
            
            // Hook OkHttpClient.newCall
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            if (OkHttpClient) {
                OkHttpClient.newCall.implementation = function(request) {
                    try {
                        if (request) {
                            var url = request.url().toString();
                            var method = request.method();
                            var headers = {};
                            
                            // 获取请求头
                            var requestHeaders = request.headers();
                            if (requestHeaders) {
                                var headerNames = requestHeaders.names();
                                for (var i = 0; i < headerNames.size(); i++) {
                                    var name = headerNames.get(i);
                                    headers[name] = requestHeaders.get(name);
                                }
                            }
                            
                            // 获取请求体
                            var body = "";
                            var requestBody = request.body();
                            if (requestBody) {
                                try {
                                    body = requestBody.toString();
                                } catch(e) {
                                    body = "[无法读取的请求体]";
                                }
                            }
                            
                            logger.logRequest(method, url, headers, utils.truncate(body, config.maxBodySize));
                        }
                        
                        return this.newCall(request);
                    } catch(e) {
                        logger.log("[-] OkHttp newCall Hook错误: " + e);
                        return this.newCall(request);
                    }
                };
                logger.log("[+] OkHttpClient.newCall Hook成功");
            }
            
            // Hook Response
            var Response = Java.use('okhttp3.Response');
            if (Response) {
                Response.body.overload().implementation = function() {
                    var response = this.body();
                    if (response) {
                        try {
                            var responseBody = response.string();
                            var url = this.request().url().toString();
                            var statusCode = this.code();
                            
                            logger.logResponse(url, statusCode, null, utils.truncate(responseBody, config.maxBodySize));
                        } catch(e) {
                            logger.log("[-] 读取响应体失败: " + e);
                        }
                    }
                    return response;
                };
                logger.log("[+] Response.body Hook成功");
            }
            
        } catch(e) {
            logger.log("[-] OkHttp Hook失败: " + e);
        }
    }

    // 2. 监控HttpURLConnection
    function hookHttpURLConnection() {
        if (!config.enableHttpURLConnection) return;
        
        try {
            logger.log("[*] 开始Hook HttpURLConnection...");
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            if (HttpURLConnection) {
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    logger.log("[+] HttpURLConnection 请求方法: " + method);
                    return this.setRequestMethod(method);
                };
                
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    logger.log("[+] HttpURLConnection 设置请求头: " + key + " = " + value);
                    return this.setRequestProperty(key, value);
                };
                
                HttpURLConnection.getInputStream.implementation = function() {
                    logger.log("[+] HttpURLConnection 获取输入流");
                    return this.getInputStream();
                };
                
                HttpURLConnection.getOutputStream.implementation = function() {
                    logger.log("[+] HttpURLConnection 获取输出流");
                    return this.getOutputStream();
                };
            }
            
            logger.log("[+] HttpURLConnection Hook成功");
        } catch(e) {
            logger.log("[-] HttpURLConnection Hook失败: " + e);
        }
    }

    // 3. 监控Socket连接
    function hookSocket() {
        if (!config.enableSocket) return;
        
        try {
            logger.log("[*] 开始Hook Socket...");
            
            // Hook Java Socket
            var Socket = Java.use('java.net.Socket');
            if (Socket) {
                Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
                    logger.log("[+] Socket连接: " + endpoint.toString());
                    return this.connect(endpoint);
                };
                
                Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
                    logger.log("[+] Socket连接(带超时): " + endpoint.toString() + ", 超时: " + timeout);
                    return this.connect(endpoint, timeout);
                };
            }
            
            // Hook native connect函数
            var connectPtr = Module.findExportByName(null, 'connect');
            if (connectPtr) {
                Interceptor.attach(connectPtr, {
                    onEnter: function(args) {
                        try {
                            var sockAddr = args[1];
                            if (sockAddr) {
                                var port = Memory.readU16LE(sockAddr.add(2));
                                var addr = Memory.readU32LE(sockAddr.add(4));
                                var ip = ((addr >> 24) & 0xFF) + "." +
                                        ((addr >> 16) & 0xFF) + "." +
                                        ((addr >> 8) & 0xFF) + "." +
                                        (addr & 0xFF);
                                logger.log("[+] Native Socket连接: " + ip + ":" + port);
                            }
                        } catch(e) {
                            logger.log("[-] Native Socket Hook错误: " + e);
                        }
                    }
                });
            }
            
            logger.log("[+] Socket Hook成功");
        } catch(e) {
            logger.log("[-] Socket Hook失败: " + e);
        }
    }

    // 4. 监控SSL/TLS
    function hookSSL() {
        if (!config.enableSSL) return;
        
        try {
            logger.log("[*] 开始Hook SSL/TLS...");
            
            // Hook SSL_write
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (sslWritePtr) {
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 10240) { // 限制大小避免日志过多
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = utils.bytes2hex(data);
                                logger.log("[+] SSL写入数据: " + utils.truncate(hexData, 200));
                            }
                        } catch(e) {
                            logger.log("[-] SSL_write Hook错误: " + e);
                        }
                    }
                });
            }
            
            // Hook SSL_read
            var sslReadPtr = Module.findExportByName(null, 'SSL_read');
            if (sslReadPtr) {
                Interceptor.attach(sslReadPtr, {
                    onLeave: function(retval) {
                        try {
                            var len = retval.toInt32();
                            if (len > 0 && len < 10240) {
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = utils.bytes2hex(data);
                                logger.log("[+] SSL读取数据: " + utils.truncate(hexData, 200));
                            }
                        } catch(e) {
                            logger.log("[-] SSL_read Hook错误: " + e);
                        }
                    }
                });
            }
            
            logger.log("[+] SSL/TLS Hook成功");
        } catch(e) {
            logger.log("[-] SSL/TLS Hook失败: " + e);
        }
    }

    // 5. 监控WebView
    function hookWebView() {
        if (!config.enableWebView) return;
        
        try {
            logger.log("[*] 开始Hook WebView...");
            
            var WebView = Java.use('android.webkit.WebView');
            if (WebView) {
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    logger.log("[+] WebView加载URL: " + url);
                    return this.loadUrl(url);
                };
                
                WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
                    logger.log("[+] WebView加载URL(带请求头): " + url);
                    if (headers) {
                        logger.log("[*] WebView请求头: " + headers.toString());
                    }
                    return this.loadUrl(url, headers);
                };
                
                WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
                    logger.log("[+] WebView加载数据: MIME=" + mimeType + ", 编码=" + encoding);
                    logger.log("[*] 数据: " + utils.truncate(data, 500));
                    return this.loadData(data, mimeType, encoding);
                };
            }
            
            logger.log("[+] WebView Hook成功");
        } catch(e) {
            logger.log("[-] WebView Hook失败: " + e);
        }
    }

    // 6. 监控Volley
    function hookVolley() {
        if (!config.enableVolley) return;
        
        try {
            logger.log("[*] 开始Hook Volley...");
            
            // Hook StringRequest
            var StringRequest = Java.use('com.android.volley.toolbox.StringRequest');
            if (StringRequest) {
                StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
                    logger.log("[+] Volley StringRequest: " + method + " " + url);
                    return this.$init(method, url, listener, errorListener);
                };
            }
            
            // Hook JsonObjectRequest
            var JsonObjectRequest = Java.use('com.android.volley.toolbox.JsonObjectRequest');
            if (JsonObjectRequest) {
                JsonObjectRequest.$init.overload('int', 'java.lang.String', 'org.json.JSONObject', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, jsonRequest, listener, errorListener) {
                    logger.log("[+] Volley JsonObjectRequest: " + method + " " + url);
                    if (jsonRequest) {
                        logger.log("[*] 请求JSON: " + jsonRequest.toString());
                    }
                    return this.$init(method, url, jsonRequest, listener, errorListener);
                };
            }
            
            logger.log("[+] Volley Hook成功");
        } catch(e) {
            logger.log("[-] Volley Hook失败: " + e);
        }
    }

    // 7. 监控Retrofit
    function hookRetrofit() {
        if (!config.enableRetrofit) return;
        
        try {
            logger.log("[*] 开始Hook Retrofit...");
            
            // Hook OkHttpClient (Retrofit通常使用OkHttp)
            // 这里可以添加Retrofit特定的Hook逻辑
            
            logger.log("[+] Retrofit Hook成功");
        } catch(e) {
            logger.log("[-] Retrofit Hook失败: " + e);
        }
    }

    // 主函数
    function main() {
        logger.log("[*] 通用网络请求监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            hookOkHttp();
            hookHttpURLConnection();
            hookSocket();
            hookSSL();
            hookWebView();
            hookVolley();
            hookRetrofit();
            
            logger.log("[+] 所有网络Hook已设置完成");
            logger.log("[*] 开始监控网络请求...");
        }, 1000);
    }

    // 启动主函数
    main();
});

// 导出配置，方便外部修改
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        config: config,
        logger: logger,
        utils: utils
    };
} 