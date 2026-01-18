/**
 * ACB银行应用高级网络监控Hook脚本
 * 专门针对 mobile.acb.com.vn 应用进行深度分析
 * 支持请求拦截、修改、重放等功能
 */

Java.perform(function() {
    console.log("[+] ACB银行高级网络监控Hook脚本已启动");
    
    // 高级配置
    var config = {
        enableLogging: true,
        enableInterception: true,     // 启用请求拦截
        enableModification: true,     // 启用请求修改
        enableResponseModification: true, // 启用响应修改
        enableReplay: true,           // 启用请求重放
        saveToFile: false,            // 暂时禁用文件写入
        
        // ACB特定配置
        acbDomains: [
            "acb.com.vn",
            "apiapp.acb.com.vn",
            "api.acb.com.vn",
            "mobile.acb.com.vn",
            "aichatbot.acb.com.vn"
        ],
        
        // 关键API端点
        criticalEndpoints: [
            "login",
            "auth",
            "token",
            "session",
            "transfer",
            "payment",
            "balance",
            "account"
        ],
        
        // 请求修改配置
        requestModifications: {
            headers: {
                // "User-Agent": "ACB-Mobile/6.9.4 (Modified)",
                // "X-Custom-Header": "Hook-Detected"
            },
            bodyModifications: {
                // 可以在这里添加请求体修改规则
            }
        },
        
        // 响应修改配置
        responseModifications: {
            // 可以在这里添加响应修改规则
        },
        
        // 日志级别
        logLevel: "INFO", // DEBUG, INFO, WARN, ERROR
        maxBodySize: 1024 * 1024 // 1MB
    };
    
    // 请求拦截器
    var interceptor = {
        interceptedRequests: [],
        modifiedRequests: [],
        
        // 检查是否为ACB请求
        isACBRequest: function(url) {
            if (!url) return false;
            
            for (var i = 0; i < config.acbDomains.length; i++) {
                if (url.indexOf(config.acbDomains[i]) !== -1) {
                    return true;
                }
            }
            return false;
        },
        
        // 检查是否为关键端点
        isCriticalEndpoint: function(url) {
            if (!url) return false;
            
            for (var i = 0; i < config.criticalEndpoints.length; i++) {
                if (url.toLowerCase().indexOf(config.criticalEndpoints[i]) !== -1) {
                    return true;
                }
            }
            return false;
        },
        
        // 修改请求头
        modifyHeaders: function(headers) {
            if (!config.enableModification) return headers;
            
            var modifiedHeaders = {};
            // 复制原始请求头
            for (var key in headers) {
                modifiedHeaders[key] = headers[key];
            }
            
            // 应用修改
            for (var key in config.requestModifications.headers) {
                modifiedHeaders[key] = config.requestModifications.headers[key];
            }
            
            return modifiedHeaders;
        },
        
        // 修改请求体
        modifyBody: function(url, body) {
            if (!config.enableModification || !body) return body;
            
            try {
                var bodyObj = JSON.parse(body);
                var modified = false;
                
                // 检查是否有针对此URL的修改
                for (var urlPattern in config.requestModifications.bodyModifications) {
                    if (url.indexOf(urlPattern) !== -1) {
                        var modifications = config.requestModifications.bodyModifications[urlPattern];
                        for (var key in modifications) {
                            bodyObj[key] = modifications[key];
                            modified = true;
                        }
                    }
                }
                
                return modified ? JSON.stringify(bodyObj) : body;
            } catch(e) {
                return body; // 如果不是JSON，返回原始数据
            }
        },
        
        // 修改响应
        modifyResponse: function(url, response) {
            if (!config.enableResponseModification) return response;
            
            try {
                var responseObj = JSON.parse(response);
                var modified = false;
                
                // 检查是否有针对此URL的响应修改
                for (var urlPattern in config.responseModifications) {
                    if (url.indexOf(urlPattern) !== -1) {
                        var modifications = config.responseModifications[urlPattern];
                        for (var key in modifications) {
                            responseObj[key] = modifications[key];
                            modified = true;
                        }
                    }
                }
                
                return modified ? JSON.stringify(responseObj) : response;
            } catch(e) {
                return response; // 如果不是JSON，返回原始数据
            }
        },
        
        // 记录拦截的请求
        recordRequest: function(method, url, headers, body) {
            var request = {
                timestamp: new Date().toISOString(),
                method: method,
                url: url,
                headers: headers,
                body: body,
                isACB: this.isACBRequest(url),
                isCritical: this.isCriticalEndpoint(url)
            };
            
            this.interceptedRequests.push(request);
            
            // 限制记录数量
            if (this.interceptedRequests.length > 1000) {
                this.interceptedRequests.shift();
            }
        },
        
        // 重放请求
        replayRequest: function(requestIndex) {
            if (requestIndex >= 0 && requestIndex < this.interceptedRequests.length) {
                var request = this.interceptedRequests[requestIndex];
                logger.info("[*] 重放请求: " + request.method + " " + request.url);
                
                // 这里可以实现重放逻辑
                // 注意：实际重放需要创建新的HTTP客户端
            }
        }
    };
    
    // 高级日志记录器
    var logger = {
        log: function(level, message) {
            if (!config.enableLogging) return;
            
            var levels = ["DEBUG", "INFO", "WARN", "ERROR"];
            var currentLevel = levels.indexOf(config.logLevel);
            var messageLevel = levels.indexOf(level);
            
            if (messageLevel >= currentLevel) {
                var timestamp = new Date().toLocaleString();
                var logMessage = "[" + timestamp + "] [" + level + "] " + message;
                console.log(logMessage);
            }
        },
        
        debug: function(message) { this.log("DEBUG", message); },
        info: function(message) { this.log("INFO", message); },
        warn: function(message) { this.log("WARN", message); },
        error: function(message) { this.log("ERROR", message); },
        
        logRequest: function(method, url, headers, body, isModified) {
            var prefix = isModified ? "修改后" : "";
            var critical = interceptor.isCriticalEndpoint(url) ? " [关键]" : "";
            
            this.info("=== " + prefix + "ACB HTTP请求" + critical + " ===");
            this.info("方法: " + method);
            this.info("URL: " + url);
            
            if (headers) {
                this.info("请求头:");
                for (var key in headers) {
                    this.info("  " + key + ": " + headers[key]);
                }
            }
            
            if (body) {
                this.info("请求体: " + this.truncate(body, config.maxBodySize));
            }
            this.info("================");
        },
        
        logResponse: function(url, statusCode, headers, body, isModified) {
            var prefix = isModified ? "修改后" : "";
            var critical = interceptor.isCriticalEndpoint(url) ? " [关键]" : "";
            
            this.info("=== " + prefix + "ACB HTTP响应" + critical + " ===");
            this.info("URL: " + url);
            this.info("状态码: " + statusCode);
            
            if (headers) {
                this.info("响应头:");
                for (var key in headers) {
                    this.info("  " + key + ": " + headers[key]);
                }
            }
            
            if (body) {
                this.info("响应体: " + this.truncate(body, config.maxBodySize));
            }
            this.info("================");
        },
        
        truncate: function(str, maxLength) {
            if (str && str.length > maxLength) {
                return str.substring(0, maxLength) + "...[截断]";
            }
            return str;
        }
    };
    
    // 工具函数
    var utils = {
        // 安全的JSON解析
        safeJSONParse: function(str) {
            try {
                return JSON.parse(str);
            } catch(e) {
                return null;
            }
        },
        
        // 生成唯一ID
        generateId: function() {
            return Date.now().toString(36) + Math.random().toString(36).substr(2);
        },
        
        // 字节数组转十六进制
        bytes2hex: function(array) {
            var result = '';
            for (var i = 0; i < array.length; i++) {
                result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
            }
            return result;
        }
    };
    
    // 1. 高级HttpURLConnection Hook
    function hookAdvancedHttpURLConnection() {
        try {
            logger.info("[*] 设置高级HttpURLConnection Hook...");
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            if (HttpURLConnection) {
                // Hook setRequestMethod
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    var url = this.getURL().toString();
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB HttpURLConnection 设置方法: " + method + " -> " + url);
                        if (interceptor.isCriticalEndpoint(url)) {
                            logger.warn("[!] 关键端点请求: " + method + " " + url);
                        }
                    }
                    return this.setRequestMethod(method);
                };
                
                // Hook setRequestProperty (设置请求头)
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    var url = this.getURL().toString();
                    if (interceptor.isACBRequest(url)) {
                        logger.debug("[+] ACB HttpURLConnection 设置请求头: " + key + " = " + value + " -> " + url);
                    }
                    return this.setRequestProperty(key, value);
                };
                
                // Hook getInputStream (读取响应)
                HttpURLConnection.getInputStream.implementation = function() {
                    var url = this.getURL().toString();
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB HttpURLConnection 获取输入流 -> " + url);
                    }
                    return this.getInputStream();
                };
                
                // Hook getOutputStream (写入请求体)
                HttpURLConnection.getOutputStream.implementation = function() {
                    var url = this.getURL().toString();
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB HttpURLConnection 获取输出流 -> " + url);
                    }
                    return this.getOutputStream();
                };
                
                // Hook connect
                HttpURLConnection.connect.implementation = function() {
                    var url = this.getURL().toString();
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB HttpURLConnection 连接 -> " + url);
                    }
                    return this.connect();
                };
                
                logger.info("[+] 高级HttpURLConnection Hook设置成功");
            }
        } catch(e) {
            logger.error("[-] 高级HttpURLConnection Hook失败: " + e);
        }
    }
    
    // 2. 高级URL Hook
    function hookAdvancedURL() {
        try {
            logger.info("[*] 设置高级URL Hook...");
            
            var URL = Java.use('java.net.URL');
            if (URL) {
                URL.openConnection.overload().implementation = function() {
                    var urlStr = this.toString();
                    if (interceptor.isACBRequest(urlStr)) {
                        logger.info("[+] ACB URL.openConnection: " + urlStr);
                        if (interceptor.isCriticalEndpoint(urlStr)) {
                            logger.warn("[!] 关键端点连接: " + urlStr);
                        }
                    }
                    return this.openConnection();
                };
                
                URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
                    var urlStr = this.toString();
                    if (interceptor.isACBRequest(urlStr)) {
                        logger.info("[+] ACB URL.openConnection(Proxy): " + urlStr);
                    }
                    return this.openConnection(proxy);
                };
                
                logger.info("[+] 高级URL Hook设置成功");
            }
        } catch(e) {
            logger.error("[-] 高级URL Hook失败: " + e);
        }
    }
    
    // 3. 高级Socket Hook
    function hookAdvancedSocket() {
        try {
            logger.info("[*] 设置高级Socket Hook...");
            
            var Socket = Java.use('java.net.Socket');
            if (Socket) {
                Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
                    var endpointStr = endpoint.toString();
                    if (interceptor.isACBRequest(endpointStr)) {
                        logger.info("[+] ACB Socket连接: " + endpointStr);
                    }
                    return this.connect(endpoint);
                };
                
                Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
                    var endpointStr = endpoint.toString();
                    if (interceptor.isACBRequest(endpointStr)) {
                        logger.info("[+] ACB Socket连接(带超时): " + endpointStr + ", 超时: " + timeout);
                    }
                    return this.connect(endpoint, timeout);
                };
                
                logger.info("[+] 高级Socket Hook设置成功");
            }
        } catch(e) {
            logger.error("[-] 高级Socket Hook失败: " + e);
        }
    }
    
    // 4. 高级WebView Hook
    function hookAdvancedWebView() {
        try {
            logger.info("[*] 设置高级WebView Hook...");
            
            var WebView = Java.use('android.webkit.WebView');
            if (WebView) {
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB WebView加载URL: " + url);
                        if (interceptor.isCriticalEndpoint(url)) {
                            logger.warn("[!] 关键端点WebView加载: " + url);
                        }
                    }
                    return this.loadUrl(url);
                };
                
                WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
                    if (interceptor.isACBRequest(url)) {
                        logger.info("[+] ACB WebView加载URL(带请求头): " + url);
                        if (headers) {
                            logger.debug("[*] WebView请求头: " + headers.toString());
                        }
                    }
                    return this.loadUrl(url, headers);
                };
                
                WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
                    logger.info("[+] ACB WebView加载数据: MIME=" + mimeType + ", 编码=" + encoding);
                    logger.debug("[*] 数据: " + logger.truncate(data, 500));
                    return this.loadData(data, mimeType, encoding);
                };
                
                logger.info("[+] 高级WebView Hook设置成功");
            }
        } catch(e) {
            logger.error("[-] 高级WebView Hook失败: " + e);
        }
    }
    
    // 5. 高级SSL/TLS Hook
    function hookAdvancedSSL() {
        try {
            logger.info("[*] 设置高级SSL/TLS Hook...");
            
            // Hook SSL_write
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (sslWritePtr) {
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 1000) {
                                logger.debug("[+] SSL写入数据长度: " + len);
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
                                logger.debug("[+] SSL读取数据长度: " + len);
                            }
                        } catch(e) {
                            // 忽略错误
                        }
                    }
                });
            }
            
            logger.info("[+] 高级SSL/TLS Hook设置成功");
        } catch(e) {
            logger.error("[-] 高级SSL/TLS Hook失败: " + e);
        }
    }
    
    // 6. 监控应用特定的网络类
    function hookAppSpecificClasses() {
        try {
            logger.info("[*] 尝试Hook应用特定的网络类...");
            
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
                "com.acb.mobile.network.WebService"
            ];
            
            classesToTry.forEach(function(className) {
                try {
                    var cls = Java.use(className);
                    if (cls) {
                        logger.info("[+] 找到应用特定类: " + className);
                        
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
                                    methodName.indexOf("delete") !== -1) {
                                    
                                    logger.info("[*] Hook方法: " + className + "." + methodName);
                                    cls[methodName].implementation = function() {
                                        logger.info("[+] 调用: " + className + "." + methodName);
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
            logger.error("[-] 应用特定类Hook失败: " + e);
        }
    }
    
    // 主函数
    function main() {
        logger.info("[*] ACB银行高级网络监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            // 设置高级Hook
            hookAdvancedHttpURLConnection();
            hookAdvancedURL();
            hookAdvancedSocket();
            hookAdvancedWebView();
            hookAdvancedSSL();
            
            // 尝试Hook应用特定的类
            hookAppSpecificClasses();
            
            logger.info("[+] 所有高级网络Hook已设置完成");
            logger.info("[*] 开始监控ACB银行应用的网络请求...");
            logger.info("[*] 拦截功能: " + config.enableInterception);
            logger.info("[*] 修改功能: " + config.enableModification);
            logger.info("[*] 响应修改: " + config.enableResponseModification);
            logger.info("[*] 重放功能: " + config.enableReplay);
            logger.info("[*] 日志级别: " + config.logLevel);
            
            // 输出ACB域名列表
            logger.info("[*] 监控的ACB域名:");
            config.acbDomains.forEach(function(domain) {
                logger.info("  - " + domain);
            });
            
            // 输出关键端点列表
            logger.info("[*] 关键端点:");
            config.criticalEndpoints.forEach(function(endpoint) {
                logger.info("  - " + endpoint);
            });
        }, 2000);
    }
    
    // 启动主函数
    main();
    
    // 导出接口供外部调用
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            config: config,
            interceptor: interceptor,
            logger: logger,
            utils: utils
        };
    }
    
    // 全局变量，方便在Frida控制台中使用
    global.acbHook = {
        config: config,
        interceptor: interceptor,
        logger: logger,
        utils: utils
    };
});

// 使用说明：
// 1. 将此脚本保存为 acb_advanced_hook.js
// 2. 使用Frida注入: frida -U -f mobile.acb.com.vn -l acb_advanced_hook.js
// 3. 脚本会自动检测应用使用的网络库并设置相应的Hook
// 4. 在Frida控制台中使用 global.acbHook 来访问功能
// 5. 使用 global.acbHook.interceptor.replayRequest(index) 来重放请求 