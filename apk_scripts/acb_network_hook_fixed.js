/**
 * ACB银行应用网络请求监控Hook脚本 (修复版)
 * 专门针对 mobile.acb.com.vn 应用
 * 自动检测网络库并设置相应的Hook
 */

Java.perform(function() {
    console.log("[+] ACB银行网络监控Hook脚本已启动");
    
    // 配置
    var config = {
        enableLogging: true,
        saveToFile: false,  // 暂时禁用文件写入，避免错误
        logFile: "/sdcard/acb_network.log",
        maxBodySize: 1024 * 1024, // 1MB
        logHeaders: true,
        logBody: true,
        logResponse: true,
        filterACB: true,    // 只显示ACB相关的请求
        showThirdParty: false // 是否显示第三方服务请求
    };
    
    // 日志记录器
    var logger = {
        log: function(message) {
            if (!config.enableLogging) return;
            
            var timestamp = new Date().toLocaleString();
            var logMessage = "[" + timestamp + "] " + message;
            console.log(logMessage);
            
            // 暂时禁用文件写入，避免java未定义错误
            /*
            if (config.saveToFile) {
                try {
                    var FileWriter = Java.use('java.io.FileWriter');
                    var file = FileWriter.$new(config.logFile, true);
                    file.write(logMessage + "\n");
                    file.close();
                } catch(e) {
                    console.log("[-] 写入日志文件失败: " + e);
                }
            }
            */
        },
        
        logRequest: function(method, url, headers, body) {
            // 过滤ACB相关请求
            if (config.filterACB && !this.isACBRequest(url)) {
                return;
            }
            
            this.log("=== ACB HTTP请求 ===");
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
            // 过滤ACB相关请求
            if (config.filterACB && !this.isACBRequest(url)) {
                return;
            }
            
            this.log("=== ACB HTTP响应 ===");
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
        },
        
        // 判断是否为ACB相关请求
        isACBRequest: function(url) {
            if (!url) return false;
            
            var acbDomains = [
                "acb.com.vn",
                "apiapp.acb.com.vn",
                "api.acb.com.vn",
                "mobile.acb.com.vn"
            ];
            
            for (var i = 0; i < acbDomains.length; i++) {
                if (url.indexOf(acbDomains[i]) !== -1) {
                    return true;
                }
            }
            return false;
        },
        
        // 判断是否为第三方服务请求
        isThirdPartyRequest: function(url) {
            if (!url) return false;
            
            var thirdPartyDomains = [
                "appsflyer.com",
                "useinsider.com",
                "firebase",
                "googleapis.com",
                "azureedge.net"
            ];
            
            for (var i = 0; i < thirdPartyDomains.length; i++) {
                if (url.indexOf(thirdPartyDomains[i]) !== -1) {
                    return true;
                }
            }
            return false;
        }
    };
    
    // 网络库检测器
    var networkDetector = {
        detectedLibraries: [],
        
        // 检测已加载的网络库
        detectLibraries: function() {
            logger.log("[*] 开始检测网络库...");
            
            var libraries = [
                { name: "OkHttp", class: "okhttp3.OkHttpClient" },
                { name: "HttpURLConnection", class: "java.net.HttpURLConnection" },
                { name: "Apache HttpClient", class: "org.apache.http.impl.client.DefaultHttpClient" },
                { name: "Volley", class: "com.android.volley.toolbox.StringRequest" },
                { name: "Retrofit", class: "retrofit2.Retrofit" },
                { name: "WebView", class: "android.webkit.WebView" },
                { name: "Socket", class: "java.net.Socket" }
            ];
            
            libraries.forEach(function(lib) {
                try {
                    var cls = Java.use(lib.class);
                    if (cls) {
                        this.detectedLibraries.push(lib.name);
                        logger.log("[+] 检测到网络库: " + lib.name);
                    }
                } catch(e) {
                    // 库不存在，忽略
                }
            }.bind(this));
            
            logger.log("[*] 检测完成，发现网络库: " + this.detectedLibraries.join(", "));
            return this.detectedLibraries;
        }
    };
    
    // 1. 通用HttpURLConnection Hook (最基础，几乎所有应用都使用)
    function hookHttpURLConnection() {
        try {
            logger.log("[*] 设置HttpURLConnection Hook...");
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            if (HttpURLConnection) {
                // Hook setRequestMethod
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    var url = this.getURL().toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] HttpURLConnection 设置方法: " + method + " -> " + url);
                    }
                    return this.setRequestMethod(method);
                };
                
                // Hook setRequestProperty (设置请求头)
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    var url = this.getURL().toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] HttpURLConnection 设置请求头: " + key + " = " + value + " -> " + url);
                    }
                    return this.setRequestProperty(key, value);
                };
                
                // Hook getInputStream (读取响应)
                HttpURLConnection.getInputStream.implementation = function() {
                    var url = this.getURL().toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] HttpURLConnection 获取输入流 -> " + url);
                    }
                    return this.getInputStream();
                };
                
                // Hook getOutputStream (写入请求体)
                HttpURLConnection.getOutputStream.implementation = function() {
                    var url = this.getURL().toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] HttpURLConnection 获取输出流 -> " + url);
                    }
                    return this.getOutputStream();
                };
                
                // Hook connect
                HttpURLConnection.connect.implementation = function() {
                    var url = this.getURL().toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] HttpURLConnection 连接 -> " + url);
                    }
                    return this.connect();
                };
                
                logger.log("[+] HttpURLConnection Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] HttpURLConnection Hook失败: " + e);
        }
    }
    
    // 2. URL类Hook (用于监控URL创建)
    function hookURL() {
        try {
            logger.log("[*] 设置URL Hook...");
            
            var URL = Java.use('java.net.URL');
            if (URL) {
                URL.openConnection.overload().implementation = function() {
                    var urlStr = this.toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(urlStr)) {
                        logger.log("[+] URL.openConnection: " + urlStr);
                    }
                    return this.openConnection();
                };
                
                URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
                    var urlStr = this.toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(urlStr)) {
                        logger.log("[+] URL.openConnection(Proxy): " + urlStr);
                    }
                    return this.openConnection(proxy);
                };
                
                logger.log("[+] URL Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] URL Hook失败: " + e);
        }
    }
    
    // 3. Socket Hook
    function hookSocket() {
        try {
            logger.log("[*] 设置Socket Hook...");
            
            var Socket = Java.use('java.net.Socket');
            if (Socket) {
                Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
                    var endpointStr = endpoint.toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(endpointStr)) {
                        logger.log("[+] Socket连接: " + endpointStr);
                    }
                    return this.connect(endpoint);
                };
                
                Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
                    var endpointStr = endpoint.toString();
                    if (config.showThirdParty || !logger.isThirdPartyRequest(endpointStr)) {
                        logger.log("[+] Socket连接(带超时): " + endpointStr + ", 超时: " + timeout);
                    }
                    return this.connect(endpoint, timeout);
                };
                
                logger.log("[+] Socket Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] Socket Hook失败: " + e);
        }
    }
    
    // 4. WebView Hook
    function hookWebView() {
        try {
            logger.log("[*] 设置WebView Hook...");
            
            var WebView = Java.use('android.webkit.WebView');
            if (WebView) {
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] WebView加载URL: " + url);
                    }
                    return this.loadUrl(url);
                };
                
                WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
                    if (config.showThirdParty || !logger.isThirdPartyRequest(url)) {
                        logger.log("[+] WebView加载URL(带请求头): " + url);
                        if (headers) {
                            logger.log("[*] WebView请求头: " + headers.toString());
                        }
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
    
    // 5. SSL/TLS Hook
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
    
    // 6. 尝试Hook OkHttp (如果存在)
    function hookOkHttp() {
        try {
            logger.log("[*] 尝试设置OkHttp Hook...");
            
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
                logger.log("[+] OkHttp Hook设置成功");
            } else {
                logger.log("[-] OkHttp库未找到");
            }
        } catch(e) {
            logger.log("[-] OkHttp Hook失败: " + e);
        }
    }
    
    // 7. 监控应用特定的网络类
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
                "com.acb.mobile.network.ApiService"
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
                                    methodName.indexOf("get") !== -1) {
                                    
                                    logger.log("[*] Hook方法: " + className + "." + methodName);
                                    cls[methodName].implementation = function() {
                                        logger.log("[+] 调用: " + className + "." + methodName);
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
        logger.log("[*] ACB银行网络监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            // 检测网络库
            networkDetector.detectLibraries();
            
            // 设置基础Hook (这些几乎总是可用的)
            hookHttpURLConnection();
            hookURL();
            hookSocket();
            hookWebView();
            hookSSL();
            
            // 尝试设置特定库的Hook
            hookOkHttp();
            
            // 尝试Hook应用特定的类
            hookAppSpecificClasses();
            
            logger.log("[+] 所有网络Hook已设置完成");
            logger.log("[*] 开始监控ACB银行应用的网络请求...");
            logger.log("[*] 过滤设置: 只显示ACB相关请求 = " + config.filterACB);
            logger.log("[*] 显示第三方请求 = " + config.showThirdParty);
        }, 2000); // 增加延迟时间，确保应用完全加载
    }
    
    // 启动主函数
    main();
});

// 使用说明：
// 1. 将此脚本保存为 acb_network_hook_fixed.js
// 2. 使用Frida注入: frida -U -f mobile.acb.com.vn -l acb_network_hook_fixed.js
// 3. 脚本会自动检测应用使用的网络库并设置相应的Hook
// 4. 默认只显示ACB相关的网络请求，避免第三方服务干扰 