/*
 * jshook classes12.dex网络抓包脚本
 * 专门针对classes12.dex中的OkHttp3Client
 */

console.log("[+] jshook classes12.dex网络抓包脚本已启动");

// 配置选项
var CONFIG = {
    filter: {
        enabled: false,
        domains: [],
        keywords: []
    },
    log: {
        showTimestamp: true,
        maxBodyLength: 500
    }
};

// 请求计数器
var requestCounter = 0;

// 格式化日志
function formatLog(message) {
    var timestamp = '';
    if (CONFIG.log.showTimestamp) {
        var now = new Date();
        timestamp = '[' + now.toISOString() + '] ';
    }
    requestCounter++;
    return timestamp + message + ' #' + requestCounter;
}

// 安全字符串处理
function safeStr(str) {
    if (!str) return "";
    if (typeof str !== "string") str = str + "";
    return str.replace(/\r|\n/g, " ").substring(0, CONFIG.log.maxBodyLength);
}

// 网络请求日志函数
function logRequest(type, url, method, headers, body) {
    var log = [];
    log.push("========== [" + type + " 请求] ==========");
    log.push("URL: " + (url || "未知"));
    if (method) log.push("方法: " + method);
    
    if (headers && headers.length > 0) {
        log.push("请求头:");
        headers.forEach(function(header) {
            log.push("  " + header.name + ": " + header.value);
        });
    }
    
    if (body) {
        log.push("请求体: " + safeStr(body));
    }
    
    log.push("=====================================");
    
    console.log(formatLog(log.join('\n')));
}

// 开始Hook
Java.perform(function() {
    console.log(formatLog("[+] 开始设置classes12.dex网络Hook..."));
    
    // 1. 首先尝试标准OkHttp3类名
    console.log(formatLog("[*] 尝试Hook标准OkHttp3类..."));
    
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        console.log(formatLog("[+] 找到标准OkHttpClient类"));
        
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
                
                logRequest("OkHttp3", url, method, headers);
            } catch (e) {
                console.log(formatLog("[-] OkHttp3 Hook错误: " + e));
            }
            
            return this.newCall(request);
        };
        
        console.log(formatLog("[+] 标准OkHttpClient Hook设置成功"));
    } catch (e) {
        console.log(formatLog("[-] 标准OkHttpClient类不存在，尝试查找混淆类"));
    }
    
    // 2. 搜索classes12.dex中的网络类
    console.log(formatLog("[*] 搜索classes12.dex中的网络类..."));
    
    var searchCount = 0;
    var maxSearchCount = 500; // 限制搜索数量
    var foundClasses = [];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            searchCount++;
            if (searchCount > maxSearchCount) {
                return; // 停止搜索
            }
            
            // 搜索可能的网络相关类
            if (className.indexOf("okhttp") !== -1 || 
                className.indexOf("http") !== -1 ||
                className.indexOf("network") !== -1 ||
                className.indexOf("client") !== -1 ||
                className.indexOf("request") !== -1 ||
                className.indexOf("response") !== -1 ||
                className.length < 15) { // 短类名可能是混淆的
                
                foundClasses.push(className);
                
                try {
                    var clazz = Java.use(className);
                    
                    // 检查newCall方法（OkHttpClient特征）
                    if (clazz.newCall && typeof clazz.newCall === 'function') {
                        console.log(formatLog("[!] 发现可能的OkHttpClient类: " + className));
                        
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
                                    
                                    logRequest("OkHttp3", url, method, headers);
                                } catch (e) {
                                    console.log(formatLog("[-] OkHttp3 Hook错误: " + e));
                                }
                                
                                return this.newCall(request);
                            };
                            console.log(formatLog("[+] 成功Hook OkHttpClient: " + className));
                        } catch (e) {
                            console.log(formatLog("[-] Hook OkHttpClient失败: " + e));
                        }
                    }
                    
                    // 检查execute方法（Call特征）
                    if (clazz.execute && typeof clazz.execute === 'function') {
                        console.log(formatLog("[!] 发现可能的Call类: " + className));
                        
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
                                    
                                    logRequest("OkHttp3 Call", url, method, headers);
                                } catch (e) {
                                    console.log(formatLog("[-] OkHttp3 Call Hook错误: " + e));
                                }
                                
                                return this.execute();
                            };
                            console.log(formatLog("[+] 成功Hook Call: " + className));
                        } catch (e) {
                            console.log(formatLog("[-] Hook Call失败: " + e));
                        }
                    }
                    
                    // 检查string方法（ResponseBody特征）
                    if (clazz.string && typeof clazz.string === 'function') {
                        console.log(formatLog("[!] 发现可能的ResponseBody类: " + className));
                        
                        try {
                            clazz.string.implementation = function() {
                                var result = this.string();
                                try {
                                    var responseStr = safeStr(result);
                                    console.log(formatLog("[+] ResponseBody.string: " + responseStr));
                                } catch (e) {
                                    console.log(formatLog("[-] ResponseBody.string解析错误: " + e));
                                }
                                return result;
                            };
                            console.log(formatLog("[+] 成功Hook ResponseBody: " + className));
                        } catch (e) {
                            console.log(formatLog("[-] Hook ResponseBody失败: " + e));
                        }
                    }
                    
                } catch (e) {
                    // 忽略错误
                }
            }
        },
        onComplete: function() {
            console.log(formatLog("[+] 类搜索完成，搜索了 " + searchCount + " 个类"));
            console.log(formatLog("[+] 找到 " + foundClasses.length + " 个可能的网络类"));
            
            // 打印找到的类
            if (foundClasses.length > 0) {
                console.log(formatLog("[*] 找到的类列表:"));
                foundClasses.slice(0, 20).forEach(function(className) {
                    console.log(formatLog("    " + className));
                });
                if (foundClasses.length > 20) {
                    console.log(formatLog("    ... 还有 " + (foundClasses.length - 20) + " 个类"));
                }
            }
        }
    });
    
    // 3. Hook HttpURLConnection (备用方案)
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
                
                logRequest("HttpURLConnection", url, method, headers);
            } catch (e) {
                console.log(formatLog("[-] HttpURLConnection Hook错误: " + e));
            }
            
            return this.getOutputStream();
        };
        
        console.log(formatLog("[+] HttpURLConnection Hook设置成功"));
    } catch (e) {
        console.log(formatLog("[-] HttpURLConnection Hook失败: " + e));
    }
    
    // 4. Hook Socket连接
    try {
        var Socket = Java.use("java.net.Socket");
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            console.log(formatLog("[+] Socket连接: " + host + ":" + port));
            return result;
        };
        
        console.log(formatLog("[+] Socket Hook设置成功"));
    } catch(e) {
        console.log(formatLog("[-] Socket Hook失败: " + e));
    }
    
    // 5. Hook JSON解析
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        if (JSONObject) {
            JSONObject.$init.overload('java.lang.String').implementation = function(json) {
                console.log(formatLog("[+] JSON解析: " + safeStr(json)));
                return this.$init(json);
            };
        }
        
        console.log(formatLog("[+] JSON解析Hook设置成功"));
    } catch(e) {
        console.log(formatLog("[-] JSON解析Hook失败: " + e));
    }
    
    console.log(formatLog("[+] 所有网络Hook设置完成"));
    console.log(formatLog("[*] 开始监控网络请求..."));
    console.log(formatLog("[*] 现在请进行网络操作..."));
    
    // 导出配置函数
    global.updateFilter = function(newFilter) {
        CONFIG.filter = Object.assign(CONFIG.filter, newFilter);
        console.log(formatLog("[+] 过滤配置已更新"));
    };
    
    global.getConfig = function() {
        return CONFIG;
    };
    
    // 导出类查找函数
    global.searchClasses = function() {
        console.log(formatLog("[*] 重新搜索网络类..."));
        // 这里可以重新执行搜索逻辑
    };
}); 