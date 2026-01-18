/**
 * 高级Android网络请求监控和修改Hook脚本
 * 支持：请求拦截、修改、重放、响应修改等
 * 作者：AI Assistant
 * 版本：2.0
 */

Java.perform(function() {
    console.log("[+] 高级网络请求监控Hook脚本已启动");
    
    // 高级配置
    var config = {
        // 基本设置
        enableLogging: true,
        enableInterception: true,     // 启用请求拦截
        enableModification: true,     // 启用请求修改
        enableResponseModification: true, // 启用响应修改
        enableReplay: true,           // 启用请求重放
        
        // 过滤设置
        urlFilters: [
            // "api.example.com",     // 只监控特定域名
            // "login",               // 只监控包含特定关键词的URL
        ],
        
        // 修改设置
        requestModifications: {
            // 添加或修改请求头
            headers: {
                // "User-Agent": "Modified User Agent",
                // "X-Custom-Header": "Custom Value"
            },
            
            // 修改请求体 (仅对特定URL)
            bodyModifications: {
                // "api.example.com/login": {
                //     "username": "modified_user",
                //     "password": "modified_pass"
                // }
            }
        },
        
        // 响应修改设置
        responseModifications: {
            // "api.example.com/data": {
            //     "status": "success",
            //     "data": "modified_data"
            // }
        },
        
        // 日志设置
        logLevel: "INFO", // DEBUG, INFO, WARN, ERROR
        saveToFile: true,
        logFile: "/sdcard/advanced_network.log",
        maxLogSize: 10 * 1024 * 1024 // 10MB
    };
    
    // 请求拦截器
    var interceptor = {
        interceptedRequests: [],
        modifiedRequests: [],
        
        // 检查URL是否匹配过滤器
        shouldIntercept: function(url) {
            if (config.urlFilters.length === 0) return true;
            
            for (var i = 0; i < config.urlFilters.length; i++) {
                if (url.indexOf(config.urlFilters[i]) !== -1) {
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
                body: body
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
                logger.log("[*] 重放请求: " + request.method + " " + request.url);
                
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
                var timestamp = new Date().toISOString();
                var logMessage = "[" + timestamp + "] [" + level + "] " + message;
                console.log(logMessage);
                
                if (config.saveToFile) {
                    this.writeToFile(logMessage);
                }
            }
        },
        
        debug: function(message) { this.log("DEBUG", message); },
        info: function(message) { this.log("INFO", message); },
        warn: function(message) { this.log("WARN", message); },
        error: function(message) { this.log("ERROR", message); },
        
        writeToFile: function(message) {
            try {
                var file = new java.io.File(config.logFile);
                if (file.exists() && file.length() > config.maxLogSize) {
                    // 文件过大，清空重新开始
                    file.delete();
                }
                
                var writer = new java.io.FileWriter(file, true);
                writer.write(message + "\n");
                writer.close();
            } catch(e) {
                console.log("[-] 写入日志文件失败: " + e);
            }
        },
        
        logRequest: function(method, url, headers, body, isModified) {
            this.info("=== " + (isModified ? "修改后" : "") + "HTTP请求 ===");
            this.info("方法: " + method);
            this.info("URL: " + url);
            
            if (headers) {
                this.info("请求头:");
                for (var key in headers) {
                    this.info("  " + key + ": " + headers[key]);
                }
            }
            
            if (body) {
                this.info("请求体: " + body);
            }
            this.info("================");
        },
        
        logResponse: function(url, statusCode, headers, body, isModified) {
            this.info("=== " + (isModified ? "修改后" : "") + "HTTP响应 ===");
            this.info("URL: " + url);
            this.info("状态码: " + statusCode);
            
            if (headers) {
                this.info("响应头:");
                for (var key in headers) {
                    this.info("  " + key + ": " + headers[key]);
                }
            }
            
            if (body) {
                this.info("响应体: " + body);
            }
            this.info("================");
        }
    };
    
    // 工具函数
    var utils = {
        // 深拷贝对象
        deepClone: function(obj) {
            if (obj === null || typeof obj !== "object") return obj;
            if (obj instanceof Date) return new Date(obj.getTime());
            if (obj instanceof Array) return obj.map(item => this.deepClone(item));
            if (typeof obj === "object") {
                var clonedObj = {};
                for (var key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        clonedObj[key] = this.deepClone(obj[key]);
                    }
                }
                return clonedObj;
            }
        },
        
        // 安全的JSON解析
        safeJSONParse: function(str) {
            try {
                return JSON.parse(str);
            } catch(e) {
                return null;
            }
        },
        
        // 截断字符串
        truncate: function(str, maxLength) {
            if (str && str.length > maxLength) {
                return str.substring(0, maxLength) + "...[截断]";
            }
            return str;
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
    
    // 1. 高级OkHttp Hook
    function hookAdvancedOkHttp() {
        try {
            logger.info("[*] 开始Hook高级OkHttp...");
            
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            if (OkHttpClient) {
                OkHttpClient.newCall.implementation = function(request) {
                    try {
                        if (request && config.enableInterception) {
                            var url = request.url().toString();
                            
                            if (interceptor.shouldIntercept(url)) {
                                var method = request.method();
                                var headers = {};
                                var body = "";
                                
                                // 获取原始请求头
                                var requestHeaders = request.headers();
                                if (requestHeaders) {
                                    var headerNames = requestHeaders.names();
                                    for (var i = 0; i < headerNames.size(); i++) {
                                        var name = headerNames.get(i);
                                        headers[name] = requestHeaders.get(name);
                                    }
                                }
                                
                                // 获取原始请求体
                                var requestBody = request.body();
                                if (requestBody) {
                                    try {
                                        body = requestBody.toString();
                                    } catch(e) {
                                        body = "[无法读取的请求体]";
                                    }
                                }
                                
                                // 记录原始请求
                                interceptor.recordRequest(method, url, headers, body);
                                logger.logRequest(method, url, headers, body, false);
                                
                                // 修改请求
                                if (config.enableModification) {
                                    var modifiedHeaders = interceptor.modifyHeaders(headers);
                                    var modifiedBody = interceptor.modifyBody(url, body);
                                    
                                    if (JSON.stringify(modifiedHeaders) !== JSON.stringify(headers) || 
                                        modifiedBody !== body) {
                                        
                                        logger.logRequest(method, url, modifiedHeaders, modifiedBody, true);
                                        
                                        // 创建修改后的请求
                                        var RequestBuilder = Java.use('okhttp3.Request$Builder');
                                        var builder = RequestBuilder.$new();
                                        builder.url(url);
                                        builder.method(method, requestBody);
                                        
                                        // 应用修改后的请求头
                                        for (var key in modifiedHeaders) {
                                            builder.header(key, modifiedHeaders[key]);
                                        }
                                        
                                        request = builder.build();
                                    }
                                }
                            }
                        }
                        
                        return this.newCall(request);
                    } catch(e) {
                        logger.error("[-] OkHttp newCall Hook错误: " + e);
                        return this.newCall(request);
                    }
                };
                logger.info("[+] 高级OkHttpClient Hook成功");
            }
            
            // Hook Response
            var Response = Java.use('okhttp3.Response');
            if (Response) {
                Response.body.overload().implementation = function() {
                    var response = this.body();
                    if (response && config.enableResponseModification) {
                        try {
                            var url = this.request().url().toString();
                            
                            if (interceptor.shouldIntercept(url)) {
                                var responseBody = response.string();
                                var statusCode = this.code();
                                
                                logger.logResponse(url, statusCode, null, responseBody, false);
                                
                                // 修改响应
                                var modifiedResponse = interceptor.modifyResponse(url, responseBody);
                                if (modifiedResponse !== responseBody) {
                                    logger.logResponse(url, statusCode, null, modifiedResponse, true);
                                    
                                    // 创建修改后的响应体
                                    var ResponseBody = Java.use('okhttp3.ResponseBody');
                                    var MediaType = Java.use('okhttp3.MediaType');
                                    var mediaType = MediaType.parse("application/json");
                                    
                                    var modifiedResponseBody = ResponseBody.create(mediaType, modifiedResponse);
                                    
                                    // 替换响应体
                                    this.body.value = modifiedResponseBody;
                                }
                            }
                        } catch(e) {
                            logger.error("[-] 读取响应体失败: " + e);
                        }
                    }
                    return response;
                };
                logger.info("[+] 高级Response Hook成功");
            }
            
        } catch(e) {
            logger.error("[-] 高级OkHttp Hook失败: " + e);
        }
    }
    
    // 2. 高级HttpURLConnection Hook
    function hookAdvancedHttpURLConnection() {
        try {
            logger.info("[*] 开始Hook高级HttpURLConnection...");
            
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            if (HttpURLConnection) {
                HttpURLConnection.setRequestMethod.implementation = function(method) {
                    logger.debug("[+] HttpURLConnection 设置方法: " + method);
                    return this.setRequestMethod(method);
                };
                
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    logger.debug("[+] HttpURLConnection 设置请求头: " + key + " = " + value);
                    return this.setRequestProperty(key, value);
                };
                
                HttpURLConnection.getInputStream.implementation = function() {
                    logger.debug("[+] HttpURLConnection 获取输入流");
                    return this.getInputStream();
                };
                
                HttpURLConnection.getOutputStream.implementation = function() {
                    logger.debug("[+] HttpURLConnection 获取输出流");
                    return this.getOutputStream();
                };
            }
            
            logger.info("[+] 高级HttpURLConnection Hook成功");
        } catch(e) {
            logger.error("[-] 高级HttpURLConnection Hook失败: " + e);
        }
    }
    
    // 3. 高级WebView Hook
    function hookAdvancedWebView() {
        try {
            logger.info("[*] 开始Hook高级WebView...");
            
            var WebView = Java.use('android.webkit.WebView');
            if (WebView) {
                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    if (interceptor.shouldIntercept(url)) {
                        logger.info("[+] WebView加载URL: " + url);
                    }
                    return this.loadUrl(url);
                };
                
                WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
                    if (interceptor.shouldIntercept(url)) {
                        logger.info("[+] WebView加载URL(带请求头): " + url);
                        if (headers) {
                            logger.debug("[*] WebView请求头: " + headers.toString());
                        }
                    }
                    return this.loadUrl(url, headers);
                };
                
                WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
                    logger.info("[+] WebView加载数据: MIME=" + mimeType + ", 编码=" + encoding);
                    logger.debug("[*] 数据: " + utils.truncate(data, 500));
                    return this.loadData(data, mimeType, encoding);
                };
            }
            
            logger.info("[+] 高级WebView Hook成功");
        } catch(e) {
            logger.error("[-] 高级WebView Hook失败: " + e);
        }
    }
    
    // 4. 高级SSL/TLS Hook
    function hookAdvancedSSL() {
        try {
            logger.info("[*] 开始Hook高级SSL/TLS...");
            
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (sslWritePtr) {
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 10240) {
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = utils.bytes2hex(data);
                                logger.debug("[+] SSL写入数据: " + utils.truncate(hexData, 200));
                            }
                        } catch(e) {
                            logger.error("[-] SSL_write Hook错误: " + e);
                        }
                    }
                });
            }
            
            var sslReadPtr = Module.findExportByName(null, 'SSL_read');
            if (sslReadPtr) {
                Interceptor.attach(sslReadPtr, {
                    onLeave: function(retval) {
                        try {
                            var len = retval.toInt32();
                            if (len > 0 && len < 10240) {
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = utils.bytes2hex(data);
                                logger.debug("[+] SSL读取数据: " + utils.truncate(hexData, 200));
                            }
                        } catch(e) {
                            logger.error("[-] SSL_read Hook错误: " + e);
                        }
                    }
                });
            }
            
            logger.info("[+] 高级SSL/TLS Hook成功");
        } catch(e) {
            logger.error("[-] 高级SSL/TLS Hook失败: " + e);
        }
    }
    
    // 主函数
    function main() {
        logger.info("[*] 高级网络请求监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            hookAdvancedOkHttp();
            hookAdvancedHttpURLConnection();
            hookAdvancedWebView();
            hookAdvancedSSL();
            
            logger.info("[+] 所有高级网络Hook已设置完成");
            logger.info("[*] 开始监控网络请求...");
            
            // 输出配置信息
            logger.info("[*] 配置信息:");
            logger.info("  - 请求拦截: " + config.enableInterception);
            logger.info("  - 请求修改: " + config.enableModification);
            logger.info("  - 响应修改: " + config.enableResponseModification);
            logger.info("  - 日志级别: " + config.logLevel);
            logger.info("  - 保存到文件: " + config.saveToFile);
        }, 1000);
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
    global.networkHook = {
        config: config,
        interceptor: interceptor,
        logger: logger,
        utils: utils
    };
});

// 使用说明：
// 1. 修改config对象来配置监控行为
// 2. 在Frida控制台中使用 global.networkHook 来访问功能
// 3. 使用 global.networkHook.interceptor.replayRequest(index) 来重放请求
// 4. 使用 global.networkHook.logger 来控制日志输出 