/*
 * 通用网络请求抓包脚本（统一日志格式版）
 * 重写console.log方法，统一日志格式，支持过滤功能
 * 支持OkHttp3/Okio/HttpURLConnection/Retrofit2，不限定域名
 * 支持代码混淆检测和动态类查找
 */

// 配置选项
var CONFIG = {
    // 过滤设置
    filter: {
        enabled: true,           // 是否启用过滤
        domains: [],             // 要过滤的域名列表，空数组表示不过滤
        keywords: [],            // 要过滤的关键词列表，空数组表示不过滤
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

// 搜索可能的OkHttp类名
function findOkHttpClasses() {
    var possibleNames = [
        "okhttp3.OkHttpClient",
        "okhttp3.Request", 
        "okhttp3.Response",
        "okhttp3.ResponseBody",
        "okhttp3.Call",
        "okhttp3.Headers",
        "okhttp3.HttpUrl",
        "okhttp3.MediaType",
        "okhttp3.RequestBody",
        "okhttp3.ResponseBody",
        "okhttp3.CookieJar",
        "okhttp3.Interceptor",
        "okhttp3.Cache",
        "okhttp3.ConnectionPool",
        "okhttp3.Dispatcher",
        "okhttp3.EventListener",
        "okhttp3.Protocol",
        "okhttp3.TlsVersion",
        "okhttp3.CipherSuite"
    ];
    
    var foundClasses = {};
    
    for (var i = 0; i < possibleNames.length; i++) {
        try {
            var className = possibleNames[i];
            var clazz = Java.use(className);
            foundClasses[className] = clazz;
            console.log("[+] 找到类: " + className);
        } catch (e) {
            // 类不存在，继续查找
        }
    }
    
    return foundClasses;
}

// 搜索可能的Retrofit类名
function findRetrofitClasses() {
    var possibleNames = [
        "retrofit2.Retrofit",
        "retrofit2.OkHttpCall",
        "retrofit2.Call",
        "retrofit2.Response",
        "retrofit2.Callback",
        "retrofit2.Converter",
        "retrofit2.http.GET",
        "retrofit2.http.POST",
        "retrofit2.http.PUT",
        "retrofit2.http.DELETE",
        "retrofit2.http.Headers",
        "retrofit2.http.Body",
        "retrofit2.http.Query",
        "retrofit2.http.Path",
        "retrofit2.http.Field",
        "retrofit2.http.Part",
        "retrofit2.http.Multipart",
        "retrofit2.http.Streaming"
    ];
    
    var foundClasses = {};
    
    for (var i = 0; i < possibleNames.length; i++) {
        try {
            var className = possibleNames[i];
            var clazz = Java.use(className);
            foundClasses[className] = clazz;
            console.log("[+] 找到类: " + className);
        } catch (e) {
            // 类不存在，继续查找
        }
    }
    
    return foundClasses;
}

// 搜索可能的Okio类名
function findOkioClasses() {
    var possibleNames = [
        "okio.Buffer",
        "okio.Source",
        "okio.Sink",
        "okio.BufferedSource",
        "okio.BufferedSink",
        "okio.RealBufferedSource",
        "okio.RealBufferedSink",
        "okio.Okio",
        "okio.ByteString",
        "okio.ForwardingSource",
        "okio.ForwardingSink",
        "okio.GzipSource",
        "okio.GzipSink",
        "okio.HashingSource",
        "okio.HashingSink",
        "okio.InflaterSource",
        "okio.DeflaterSink"
    ];
    
    var foundClasses = {};
    
    for (var i = 0; i < possibleNames.length; i++) {
        try {
            var className = possibleNames[i];
            var clazz = Java.use(className);
            foundClasses[className] = clazz;
            console.log("[+] 找到类: " + className);
        } catch (e) {
            // 类不存在，继续查找
        }
    }
    
    return foundClasses;
}

// 开始Hook
Java.perform(function() {
    console.log("[+] 通用网络请求抓包脚本（统一日志格式版）已启动");
    console.log("[+] 过滤配置: " + JSON.stringify(CONFIG.filter));
    console.log("[+] 日志配置: " + JSON.stringify(CONFIG.log));
    console.log("[*] 开始搜索网络库类...");

    // 1. 搜索并Hook Retrofit2
    console.log("[*] 搜索Retrofit2类...");
    var retrofitClasses = findRetrofitClasses();
    
    if (retrofitClasses["retrofit2.OkHttpCall"]) {
        try {
            var OkHttpCall = retrofitClasses["retrofit2.OkHttpCall"];
            
            OkHttpCall.execute.implementation = function() {
                try {
                    var request = this.originalRequest();
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
                    
                    logNetworkRequest("Retrofit2", url, method, headers, bodyStr);
                } catch (e) {
                    console.log("[-] Retrofit2 Hook错误: " + e);
                }
                
                return this.execute();
            };
            
            console.log("[+] Retrofit2 OkHttpCall Hook设置成功");
        } catch (e) {
            console.log("[-] Retrofit2 OkHttpCall Hook失败: " + e);
        }
    }

    // 2. 搜索并Hook OkHttp3
    console.log("[*] 搜索OkHttp3类...");
    var okhttpClasses = findOkHttpClasses();
    
    if (okhttpClasses["okhttp3.OkHttpClient"]) {
        try {
            var OkHttpClient = okhttpClasses["okhttp3.OkHttpClient"];
            var Request = okhttpClasses["okhttp3.Request"];
            var ResponseBody = okhttpClasses["okhttp3.ResponseBody"];

            OkHttpClient.newCall.implementation = function(request) {
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
            
            console.log("[+] OkHttp3 OkHttpClient Hook设置成功");
        } catch (e) {
            console.log("[-] OkHttp3 OkHttpClient Hook失败: " + e);
        }
    }

    if (okhttpClasses["okhttp3.ResponseBody"]) {
        try {
            var ResponseBody = okhttpClasses["okhttp3.ResponseBody"];
            
            ResponseBody.string.implementation = function() {
                var result = this.string();
                try {
                    var responseStr = safeStr(result).substring(0, CONFIG.log.maxBodyLength);
                    console.log("[+] OkHttp3 响应体: " + responseStr);
                } catch (e) {
                    console.log("[-] OkHttp3 响应体解析错误: " + e);
                }
                return result;
            };
            
            console.log("[+] OkHttp3 ResponseBody Hook设置成功");
        } catch (e) {
            console.log("[-] OkHttp3 ResponseBody Hook失败: " + e);
        }
    }

    // 3. Hook HttpURLConnection (系统自带，不会被混淆)
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

    // 4. 搜索并Hook Okio Buffer
    console.log("[*] 搜索Okio类...");
    var okioClasses = findOkioClasses();
    
    if (okioClasses["okio.Buffer"]) {
        try {
            var Buffer = okioClasses["okio.Buffer"];
            
            Buffer.write.overload('[B').implementation = function(source) {
                var result = this.write(source);
                try {
                    var data = Java.array('byte', source);
                    var stringData = bytesToString(data);
                    
                    // 检查是否包含HTTP请求数据
                    if (stringData.indexOf("GET ") === 0 || 
                        stringData.indexOf("POST ") === 0 ||
                        stringData.indexOf("PUT ") === 0 ||
                        stringData.indexOf("DELETE ") === 0 ||
                        stringData.indexOf("Host:") !== -1 ||
                        stringData.indexOf("Content-Type:") !== -1) {
                        
                        console.log("[+] Okio Buffer写入: " + source.length + " bytes");
                        console.log("    数据: " + stringData);
                        if (CONFIG.log.showHex) {
                            console.log("    十六进制: " + bytesToHex(data));
                        }
                    }
                } catch(e) {
                    // 忽略错误
                }
                return result;
            };
            
            Buffer.read.overload('[B').implementation = function(sink) {
                var result = this.read(sink);
                if (result > 0) {
                    try {
                        var data = Java.array('byte', sink);
                        var stringData = bytesToString(data);
                        
                        // 检查是否包含HTTP响应数据
                        if (stringData.indexOf("HTTP/") === 0 ||
                            stringData.indexOf("Content-Type:") !== -1 ||
                            stringData.indexOf("{") !== -1 ||
                            stringData.indexOf("[") !== -1) {
                            
                            console.log("[+] Okio Buffer读取: " + result + " bytes");
                            console.log("    数据: " + stringData);
                            if (CONFIG.log.showHex) {
                                console.log("    十六进制: " + bytesToHex(data));
                            }
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
                return result;
            };
            
            console.log("[+] Okio Buffer Hook设置成功");
        } catch(e) {
            console.log("[-] Okio Buffer Hook失败: " + e);
        }
    }

    // 5. Hook Socket连接 (系统自带，不会被混淆)
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

    // 6. Hook JSON解析 (系统自带，不会被混淆)
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
    console.log("    - Retrofit2 请求");
    console.log("    - OkHttp3 请求和响应");
    console.log("    - HttpURLConnection");
    console.log("    - Okio Buffer读写");
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
    global.findOkHttpClasses = findOkHttpClasses;
    global.findRetrofitClasses = findRetrofitClasses;
    global.findOkioClasses = findOkioClasses;
}); 