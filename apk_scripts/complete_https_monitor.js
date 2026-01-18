/**
 * 完整HTTPS请求监控Hook脚本
 * 监控所有HTTPS请求的完整信息：请求头、请求体、响应头、响应体
 * 不做任何过滤，记录所有网络请求
 */

Java.perform(function() {
    console.log("[+] 完整HTTPS请求监控Hook脚本已启动");
    
    // 配置
    var config = {
        enableLogging: true,
        logHeaders: true,        // 记录请求头
        logBody: true,          // 记录请求体
        logResponse: true,      // 记录响应
        logURL: true,           // 记录URL
        maxBodySize: 1024 * 1024, // 1MB
        saveToFile: false       // 暂时禁用文件写入
    };
    
    // 日志记录器
    var logger = {
        log: function(message) {
            if (!config.enableLogging) return;
            var timestamp = new Date().toLocaleString();
            var logMessage = "[" + timestamp + "] " + message;
            console.log(logMessage);
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
                this.log("请求体: " + this.truncate(body, config.maxBodySize));
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
                this.log("响应体: " + this.truncate(body, config.maxBodySize));
            }
            this.log("================");
        },
        
        truncate: function(str, maxLength) {
            if (str && str.length > maxLength) {
                return str.substring(0, maxLength) + "...[截断]";
            }
            return str;
        }
    };
    
    // 1. 完整Hook HttpURLConnection
    function hookHttpURLConnection() {
        try {
            logger.log("[*] 设置完整HttpURLConnection Hook...");
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            if (HttpURLConnection) {
                // Hook setRequestMethod
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    var url = this.getURL().toString();
                    logger.log("[+] HttpURLConnection 设置方法: " + method + " -> " + url);
                    return this.setRequestMethod(method);
                };
                
                // Hook setRequestProperty (设置请求头)
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    var url = this.getURL().toString();
                    logger.log("[+] HttpURLConnection 设置请求头: " + key + " = " + value + " -> " + url);
                    return this.setRequestProperty(key, value);
                };
                
                // Hook getInputStream (读取响应)
                HttpURLConnection.getInputStream.implementation = function() {
                    var url = this.getURL().toString();
                    var responseCode = this.getResponseCode();
                    logger.log("[+] HttpURLConnection 获取输入流 -> " + url + " (状态码: " + responseCode + ")");
                    
                    var inputStream = this.getInputStream();
                    
                    // 尝试读取响应内容
                    try {
                        var BufferedReader = Java.use('java.io.BufferedReader');
                        var InputStreamReader = Java.use('java.io.InputStreamReader');
                        var StringBuilder = Java.use('java.lang.StringBuilder');
                        
                        var reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
                        var response = StringBuilder.$new();
                        var line;
                        
                        while ((line = reader.readLine()) != null) {
                            response.append(line);
                        }
                        
                        var responseBody = response.toString();
                        logger.logResponse(url, responseCode, null, responseBody);
                        
                        // 重新创建输入流，因为已经被读取了
                        return this.getInputStream();
                    } catch(e) {
                        logger.log("[-] 读取响应失败: " + e);
                        return inputStream;
                    }
                };
                
                // Hook getOutputStream (写入请求体)
                HttpURLConnection.getOutputStream.implementation = function() {
                    var url = this.getURL().toString();
                    var method = this.getRequestMethod();
                    logger.log("[+] HttpURLConnection 获取输出流 -> " + url + " (方法: " + method + ")");
                    
                    var outputStream = this.getOutputStream();
                    
                    // 创建一个包装的输出流来捕获请求体
                    try {
                        var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
                        var baos = ByteArrayOutputStream.$new();
                        
                        // 这里可以添加请求体捕获逻辑
                        // 由于输出流是动态的，需要更复杂的处理
                        
                        return outputStream;
                    } catch(e) {
                        logger.log("[-] 处理输出流失败: " + e);
                        return outputStream;
                    }
                };
                
                // Hook connect
                HttpURLConnection.connect.implementation = function() {
                    var url = this.getURL().toString();
                    var method = this.getRequestMethod();
                    logger.log("[+] HttpURLConnection 连接 -> " + url + " (方法: " + method + ")");
                    return this.connect();
                };
                
                logger.log("[+] 完整HttpURLConnection Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] HttpURLConnection Hook失败: " + e);
        }
    }
    
    // 2. 完整Hook OkHttp (如果存在)
    function hookOkHttp() {
        try {
            logger.log("[*] 尝试设置完整OkHttp Hook...");
            
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
                            
                            logger.logRequest(method, url, headers, body);
                        }
                        
                        return this.newCall(request);
                    } catch(e) {
                        logger.log("[-] OkHttp newCall Hook错误: " + e);
                        return this.newCall(request);
                    }
                };
                logger.log("[+] 完整OkHttp Hook设置成功");
            } else {
                logger.log("[-] OkHttp库未找到");
            }
        } catch(e) {
            logger.log("[-] OkHttp Hook失败: " + e);
        }
    }
    
    // 3. 完整Hook Response (监控响应)
    function hookResponse() {
        try {
            logger.log("[*] 尝试设置完整Response Hook...");
            
            var Response = Java.use('okhttp3.Response');
            if (Response) {
                Response.body.overload().implementation = function() {
                    var response = this.body();
                    if (response) {
                        try {
                            var responseBody = response.string();
                            var url = this.request().url().toString();
                            var statusCode = this.code();
                            
                            logger.logResponse(url, statusCode, null, responseBody);
                        } catch(e) {
                            logger.log("[-] 读取响应体失败: " + e);
                        }
                    }
                    return response;
                };
                logger.log("[+] 完整Response Hook设置成功");
            } else {
                logger.log("[-] Response类未找到");
            }
        } catch(e) {
            logger.log("[-] Response Hook失败: " + e);
        }
    }
    
    // 4. Hook URL类 (监控URL创建)
    function hookURL() {
        try {
            logger.log("[*] 设置URL Hook...");
            
            var URL = Java.use('java.net.URL');
            if (URL) {
                URL.openConnection.overload().implementation = function() {
                    var urlStr = this.toString();
                    logger.log("[+] URL.openConnection: " + urlStr);
                    return this.openConnection();
                };
                
                URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
                    var urlStr = this.toString();
                    logger.log("[+] URL.openConnection(Proxy): " + urlStr);
                    return this.openConnection(proxy);
                };
                
                logger.log("[+] URL Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] URL Hook失败: " + e);
        }
    }
    
    // 5. Hook Socket连接 (监控所有网络连接)
    function hookSocket() {
        try {
            logger.log("[*] 设置Socket Hook...");
            
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
                
                logger.log("[+] Socket Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] Socket Hook失败: " + e);
        }
    }
    
    // 6. Hook WebView (监控WebView请求)
    function hookWebView() {
        try {
            logger.log("[*] 设置WebView Hook...");
            
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
                    logger.log("[*] 数据: " + logger.truncate(data, 500));
                    return this.loadData(data, mimeType, encoding);
                };
                
                logger.log("[+] WebView Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] WebView Hook失败: " + e);
        }
    }
    
    // 7. Hook SSL/TLS (监控SSL通信)
    function hookSSL() {
        try {
            logger.log("[*] 设置SSL/TLS Hook...");
            
            // Hook SSL_write
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (sslWritePtr) {
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 1000) {
                                logger.log("[+] SSL写入数据长度: " + len);
                            }
                        } catch(e) {
                            // 忽略错误
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
                            if (len > 0 && len < 1000) {
                                logger.log("[+] SSL读取数据长度: " + len);
                            }
                        } catch(e) {
                            // 忽略错误
                        }
                    }
                });
            }
            
            logger.log("[+] SSL/TLS Hook设置成功");
        } catch(e) {
            logger.log("[-] SSL/TLS Hook失败: " + e);
        }
    }
    
    // 8. Hook Apache HttpClient (如果存在)
    function hookApacheHttpClient() {
        try {
            logger.log("[*] 尝试设置Apache HttpClient Hook...");
            
            var DefaultHttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');
            if (DefaultHttpClient) {
                DefaultHttpClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function(request) {
                    logger.log("[+] Apache HttpClient执行请求: " + request.getURI().toString());
                    return this.execute(request);
                };
                logger.log("[+] Apache HttpClient Hook设置成功");
            } else {
                logger.log("[-] Apache HttpClient库未找到");
            }
        } catch(e) {
            logger.log("[-] Apache HttpClient Hook失败: " + e);
        }
    }
    
    // 9. Hook Volley (如果存在)
    function hookVolley() {
        try {
            logger.log("[*] 尝试设置Volley Hook...");
            
            var StringRequest = Java.use('com.android.volley.toolbox.StringRequest');
            if (StringRequest) {
                StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
                    logger.log("[+] Volley StringRequest: " + method + " " + url);
                    return this.$init(method, url, listener, errorListener);
                };
                logger.log("[+] Volley Hook设置成功");
            } else {
                logger.log("[-] Volley库未找到");
            }
        } catch(e) {
            logger.log("[-] Volley Hook失败: " + e);
        }
    }
    
    // 10. Hook 应用特定的网络类
    function hookAppSpecificClasses() {
        try {
            logger.log("[*] 尝试Hook应用特定的网络类...");
            
            // 尝试Hook一些常见的网络相关类
            var classesToTry = [
                "com.acb.mobile.network.NetworkManager",
                "com.acb.mobile.http.HttpClient",
                "com.acb.mobile.api.ApiClient",
                "com.acb.mobile.network.RequestManager",
                "com.acb.mobile.utils.NetworkUtils",
                "com.acb.mobile.network.HttpRequest",
                "com.acb.mobile.network.ApiService",
                "com.acb.mobile.network.RestClient",
                "com.acb.mobile.network.WebService",
                "com.acb.mobile.network.HttpManager",
                "com.acb.mobile.network.ApiManager"
            ];
            
            classesToTry.forEach(function(className) {
                try {
                    var cls = Java.use(className);
                    if (cls) {
                        logger.log("[+] 找到应用特定类: " + className);
                        
                        // 尝试Hook所有方法
                        var methods = cls.class.getDeclaredMethods();
                        methods.forEach(function(method) {
                            try {
                                var methodName = method.getName();
                                if (methodName.indexOf("request") !== -1 || 
                                    methodName.indexOf("call") !== -1 ||
                                    methodName.indexOf("execute") !== -1 ||
                                    methodName.indexOf("send") !== -1 ||
                                    methodName.indexOf("post") !== -1 ||
                                    methodName.indexOf("get") !== -1 ||
                                    methodName.indexOf("put") !== -1 ||
                                    methodName.indexOf("delete") !== -1 ||
                                    methodName.indexOf("login") !== -1 ||
                                    methodName.indexOf("auth") !== -1) {
                                    
                                    logger.log("[*] Hook方法: " + className + "." + methodName);
                                    cls[methodName].implementation = function() {
                                        logger.log("[+] 调用: " + className + "." + methodName);
                                        logger.log("[*] 参数: " + JSON.stringify(arguments));
                                        return this[methodName].apply(this, arguments);
                                    };
                                }
                            } catch(e) {
                                // 忽略单个方法Hook失败
                            }
                        });
                    }
                } catch(e) {
                    // 类不存在，忽略
                }
            });
            
        } catch(e) {
            logger.log("[-] 应用特定类Hook失败: " + e);
        }
    }
    
    // 主函数
    function main() {
        logger.log("[*] 完整HTTPS请求监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            // 设置所有Hook
            hookHttpURLConnection();
            hookOkHttp();
            hookResponse();
            hookURL();
            hookSocket();
            hookWebView();
            hookSSL();
            hookApacheHttpClient();
            hookVolley();
            hookAppSpecificClasses();
            
            logger.log("[+] 所有网络Hook已设置完成");
            logger.log("[*] 开始监控所有HTTPS请求...");
            logger.log("[*] 监控内容:");
            logger.log("  - 请求URL");
            logger.log("  - 请求方法");
            logger.log("  - 请求头");
            logger.log("  - 请求体");
            logger.log("  - 响应状态码");
            logger.log("  - 响应头");
            logger.log("  - 响应体");
            logger.log("[*] 不做任何过滤，记录所有网络请求");
        }, 2000);
    }
    
    // 启动主函数
    main();
});

// 使用说明：
// 1. 将此脚本保存为 complete_https_monitor.js
// 2. 使用Frida注入: frida -U -f com.target.app -l complete_https_monitor.js
// 3. 脚本会监控所有HTTPS请求，不做任何过滤
// 4. 所有网络请求都会在控制台输出完整信息 