/*
 * jshook网络请求抓包脚本
 * 适配jshook自带的frida-mod注入
 * 支持代码混淆检测和动态类查找
 */

// 配置选项
var CONFIG = {
    // 过滤设置
    filter: {
        enabled: false,          // 默认不启用过滤
        domains: [],             // 要过滤的域名列表
        keywords: [],            // 要过滤的关键词列表
        excludeDomains: [],      // 要排除的域名列表
        excludeKeywords: []      // 要排除的关键词列表
    },
    // 日志设置
    log: {
        showTimestamp: true,     // 显示时间戳
        showRequestId: true,     // 显示请求ID
        maxBodyLength: 1000,     // 最大响应体长度
        showHex: false,          // 是否显示十六进制数据
        showStack: false         // 是否显示调用栈
    }
};

// 请求计数器
var requestCounter = 0;

// 重写console.log方法
var originalLog = console.log;
console.log = function() {
    var args = Array.prototype.slice.call(arguments);
    var message = args.join(' ');
    
    // 检查是否需要过滤
    if (CONFIG.filter.enabled && shouldFilter(message)) {
        return; // 跳过这条日志
    }
    
    // 格式化日志
    var formattedMessage = formatLogMessage(message);
    
    // 调用原始console.log
    originalLog.call(console, formattedMessage);
};

// 过滤检查函数
function shouldFilter(message) {
    if (!message || typeof message !== 'string') {
        return false;
    }
    
    // 检查排除关键词
    for (var i = 0; i < CONFIG.filter.excludeKeywords.length; i++) {
        if (message.indexOf(CONFIG.filter.excludeKeywords[i]) !== -1) {
            return true;
        }
    }
    
    // 检查排除域名
    for (var i = 0; i < CONFIG.filter.excludeDomains.length; i++) {
        if (message.indexOf(CONFIG.filter.excludeDomains[i]) !== -1) {
            return true;
        }
    }
    
    // 如果设置了过滤域名，检查是否匹配
    if (CONFIG.filter.domains.length > 0) {
        var hasMatch = false;
        for (var i = 0; i < CONFIG.filter.domains.length; i++) {
            if (message.indexOf(CONFIG.filter.domains[i]) !== -1) {
                hasMatch = true;
                break;
            }
        }
        if (!hasMatch) {
            return true;
        }
    }
    
    // 如果设置了过滤关键词，检查是否匹配
    if (CONFIG.filter.keywords.length > 0) {
        var hasMatch = false;
        for (var i = 0; i < CONFIG.filter.keywords.length; i++) {
            if (message.indexOf(CONFIG.filter.keywords[i]) !== -1) {
                hasMatch = true;
                break;
            }
        }
        if (!hasMatch) {
            return true;
        }
    }
    
    return false;
}

// 格式化日志消息
function formatLogMessage(message) {
    var timestamp = '';
    if (CONFIG.log.showTimestamp) {
        var now = new Date();
        timestamp = '[' + now.toISOString() + '] ';
    }
    
    var requestId = '';
    if (CONFIG.log.showRequestId && message.indexOf('[+]') !== -1) {
        requestCounter++;
        requestId = ' #' + requestCounter;
    }
    
    return timestamp + message + requestId;
}

// 工具函数
function safeStr(str) {
    if (!str) return "";
    if (typeof str !== "string") str = str + "";
    return str.replace(/\r|\n/g, " ");
}

function bytesToHex(bytes) {
    if (!bytes || bytes.length === 0) return "";
    var hex = "";
    for (var i = 0; i < Math.min(bytes.length, 100); i++) {
        var b = bytes[i] & 0xff;
        hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    if (bytes.length > 100) hex += "...";
    return hex;
}

function bytesToString(bytes) {
    if (!bytes || bytes.length === 0) return "";
    var str = "";
    for (var i = 0; i < Math.min(bytes.length, 100); i++) {
        var b = bytes[i] & 0xff;
        if (b >= 32 && b <= 126) {
            str += String.fromCharCode(b);
        } else {
            str += ".";
        }
    }
    if (bytes.length > 100) str += "...";
    return str;
}

// 统一的网络请求日志函数
function logNetworkRequest(type, url, method, headers, body, responseCode, responseBody) {
    var log = [];
    log.push("========== [" + type + " 网络请求] ==========");
    log.push("URL: " + (url || "未知"));
    if (method) log.push("方法: " + method);
    if (responseCode) log.push("状态码: " + responseCode);
    
    if (headers && headers.length > 0) {
        log.push("请求头:");
        headers.forEach(function(header) {
            log.push("  " + header.name + ": " + header.value);
        });
    }
    
    if (body) {
        log.push("请求体: " + safeStr(body).substring(0, CONFIG.log.maxBodyLength));
    }
    
    if (responseBody) {
        log.push("响应体: " + safeStr(responseBody).substring(0, CONFIG.log.maxBodyLength));
    }
    
    log.push("==========================================");
    
    console.log(log.join('\n'));
}

// 动态查找类函数
function findClassByPattern(pattern) {
    try {
        return Java.use(pattern);
    } catch (e) {
        return null;
    }
}

// 通过方法特征识别类
function identifyClassByMethods() {
    console.log("[*] 通过方法特征识别网络类...");
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                
                // 检查是否有newCall方法（OkHttpClient特征）
                if (clazz.newCall && typeof clazz.newCall === 'function') {
                    console.log("[!] 发现可能的OkHttpClient类: " + className);
                    console.log("    方法: newCall");
                    
                    // Hook newCall方法
                    try {
                        clazz.newCall.implementation = function(request) {
                            try {
                                var url = request.url().toString();
                                var method = request.method();
                                var headers = [];
                                
                                // 获取请求头
                                var requestHeaders = request.headers();
                                for (var i = 0; i < requestHeaders.size(); i++) {
                                    headers.push({
                                        name: requestHeaders.name(i),
                                        value: requestHeaders.value(i)
                                    });
                                }
                                
                                // 获取请求体
                                var body = request.body();
                                var bodyStr = "";
                                if (body) {
                                    try {
                                        var Buffer = findClassByPattern("okio.Buffer");
                                        if (Buffer) {
                                            var buffer = Buffer.$new();
                                            body.writeTo(buffer);
                                            bodyStr = buffer.readUtf8();
                                        }
                                    } catch (e) {
                                        bodyStr = "[无法解析请求体]";
                                    }
                                }
                                
                                logNetworkRequest("OkHttp3", url, method, headers, bodyStr);
                            } catch (e) {
                                console.log("[-] OkHttp3 Hook错误: " + e);
                            }
                            
                            return this.newCall(request);
                        };
                        console.log("[+] 成功Hook OkHttpClient.newCall: " + className);
                    } catch (e) {
                        console.log("[-] Hook OkHttpClient.newCall失败: " + e);
                    }
                }
                
                // 检查是否有execute方法（Call特征）
                if (clazz.execute && typeof clazz.execute === 'function') {
                    console.log("[!] 发现可能的Call类: " + className);
                    console.log("    方法: execute");
                    
                    // Hook execute方法
                    try {
                        clazz.execute.implementation = function() {
                            try {
                                var request = this.request();
                                var url = request.url().toString();
                                var method = request.method();
                                var headers = [];
                                
                                // 获取请求头
                                var requestHeaders = request.headers();
                                for (var i = 0; i < requestHeaders.size(); i++) {
                                    headers.push({
                                        name: requestHeaders.name(i),
                                        value: requestHeaders.value(i)
                                    });
                                }
                                
                                logNetworkRequest("OkHttp3 Call", url, method, headers);
                            } catch (e) {
                                console.log("[-] OkHttp3 Call Hook错误: " + e);
                            }
                            
                            return this.execute();
                        };
                        console.log("[+] 成功Hook Call.execute: " + className);
                    } catch (e) {
                        console.log("[-] Hook Call.execute失败: " + e);
                    }
                }
                
                // 检查是否有string方法（ResponseBody特征）
                if (clazz.string && typeof clazz.string === 'function') {
                    console.log("[!] 发现可能的ResponseBody类: " + className);
                    console.log("    方法: string");
                    
                    // Hook string方法
                    try {
                        clazz.string.implementation = function() {
                            var result = this.string();
                            try {
                                var responseStr = safeStr(result).substring(0, CONFIG.log.maxBodyLength);
                                console.log("[+] ResponseBody.string: " + responseStr);
                            } catch (e) {
                                console.log("[-] ResponseBody.string解析错误: " + e);
                            }
                            return result;
                        };
                        console.log("[+] 成功Hook ResponseBody.string: " + className);
                    } catch (e) {
                        console.log("[-] Hook ResponseBody.string失败: " + e);
                    }
                }
                
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法特征识别完成");
        }
    });
}

// 开始Hook
Java.perform(function() {
    console.log("[+] jshook网络请求抓包脚本已启动");
    console.log("[+] 过滤配置: " + JSON.stringify(CONFIG.filter));
    console.log("[+] 日志配置: " + JSON.stringify(CONFIG.log));
    console.log("[*] 开始搜索网络库类...");

    // 1. 通过方法特征识别类
    identifyClassByMethods();

    // 2. Hook HttpURLConnection (系统自带，不会被混淆)
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.getOutputStream.implementation = function() {
            try {
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                var headers = [];
                
                // 获取请求头
                var fields = this.getRequestProperties();
                var keys = fields.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var k = keys[i];
                    var v = fields.get(k);
                    headers.push({name: k, value: v});
                }
                
                logNetworkRequest("HttpURLConnection", url, method, headers);
            } catch (e) {
                console.log("[-] HttpURLConnection Hook错误: " + e);
            }
            
            return this.getOutputStream();
        };

        HttpURLConnection.getInputStream.implementation = function() {
            try {
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                var code = this.getResponseCode();
                var headers = [];
                
                // 获取响应头
                var fields = this.getHeaderFields();
                var keys = fields.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var k = keys[i];
                    var v = fields.get(k);
                    headers.push({name: k, value: v});
                }
                
                logNetworkRequest("HttpURLConnection", url, method, headers, null, code);
            } catch (e) {
                console.log("[-] HttpURLConnection Hook错误: " + e);
            }
            
            return this.getInputStream();
        };

        console.log("[+] HttpURLConnection Hook设置成功");
    } catch (e) {
        console.log("[-] HttpURLConnection Hook失败: " + e);
    }

    // 3. Hook Socket连接 (系统自带，不会被混淆)
    try {
        var Socket = Java.use("java.net.Socket");
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            console.log("[+] Socket连接: " + host + ":" + port);
            return result;
        };
        
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            var result = this.connect(endpoint, timeout);
            try {
                var host = this.getInetAddress().getHostName();
                var port = this.getPort();
                console.log("[+] Socket连接(带超时): " + host + ":" + port + ", 超时: " + timeout);
            } catch(e) {
                // 忽略错误
            }
            return result;
        };
        
        console.log("[+] Socket Hook设置成功");
    } catch(e) {
        console.log("[-] Socket Hook失败: " + e);
    }

    // 4. Hook JSON解析 (系统自带，不会被混淆)
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        if (JSONObject) {
            JSONObject.$init.overload('java.lang.String').implementation = function(json) {
                console.log("[+] JSON解析: " + safeStr(json).substring(0, CONFIG.log.maxBodyLength));
                return this.$init(json);
            };
        }
        
        var Gson = Java.use("com.google.gson.Gson");
        if (Gson) {
            Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function(json, classOfT) {
                console.log("[+] Gson解析: " + safeStr(json).substring(0, CONFIG.log.maxBodyLength));
                console.log("    类型: " + classOfT.getName());
                return this.fromJson(json, classOfT);
            };
        }
        
        console.log("[+] JSON解析Hook设置成功");
    } catch(e) {
        console.log("[-] JSON解析Hook失败: " + e);
    }

    console.log("[+] 所有网络请求抓包Hook已设置完成");
    console.log("[*] 开始监控所有网络请求...");
    console.log("[*] 监控内容:");
    console.log("    - OkHttp3 请求和响应（通过方法特征识别）");
    console.log("    - HttpURLConnection");
    console.log("    - Socket连接");
    console.log("    - JSON数据解析");
    console.log("[*] 现在请进行网络操作...");
    
    // 导出配置函数供外部调用
    global.updateFilter = function(newFilter) {
        CONFIG.filter = Object.assign(CONFIG.filter, newFilter);
        console.log("[+] 过滤配置已更新: " + JSON.stringify(CONFIG.filter));
    };
    
    global.updateLogConfig = function(newLogConfig) {
        CONFIG.log = Object.assign(CONFIG.log, newLogConfig);
        console.log("[+] 日志配置已更新: " + JSON.stringify(CONFIG.log));
    };
    
    global.getConfig = function() {
        return CONFIG;
    };
    
    // 导出类查找函数
    global.identifyClassByMethods = identifyClassByMethods;
}); 