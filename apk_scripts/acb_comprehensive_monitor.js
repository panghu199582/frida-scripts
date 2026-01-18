/*
 * ACB全面网络监控脚本
 * 在多个层级监控ACB网络请求
 */

console.log("[+] ACB全面网络监控脚本已启动");

// ACB相关域名列表
var ACB_DOMAINS = [
    "acb.com.vn",
    "api.acb.com.vn", 
    "apiapp.acb.com.vn",
    "aichatbot.acb.com.vn",
    "mobile.acb.com.vn",
    "app.acb.com.vn",
    "www.acb.com.vn",
    "secure.acb.com.vn",
    "login.acb.com.vn",
    "api.acb.com",
    "mobile.acb.com"
];

// 检查是否是ACB相关域名
function isACBDomain(host) {
    if (!host) return false;
    host = host.toLowerCase();
    return ACB_DOMAINS.some(function(domain) {
        return host.indexOf(domain) !== -1;
    });
}

Java.perform(function() {
    console.log("[*] ACB全面网络监控脚本初始化...");
    console.log("[*] 监控的ACB域名: " + ACB_DOMAINS.join(", "));
    
    // 1. Hook HttpURLConnection
    try {
        console.log("[*] 设置HttpURLConnection Hook...");
        
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.getInputStream.implementation = function() {
            var result = this.getInputStream();
            try {
                var url = this.getURL().toString();
                if (isACBDomain(url)) {
                    console.log("[+] ACB HttpURLConnection.getInputStream(): " + url);
                    console.log("    方法: " + this.getRequestMethod());
                }
            } catch(e) {
                // 忽略错误
            }
            return result;
        };
        
        HttpURLConnection.getOutputStream.implementation = function() {
            var result = this.getOutputStream();
            try {
                var url = this.getURL().toString();
                if (isACBDomain(url)) {
                    console.log("[+] ACB HttpURLConnection.getOutputStream(): " + url);
                    console.log("    方法: " + this.getRequestMethod());
                }
            } catch(e) {
                // 忽略错误
            }
            return result;
        };
        
        console.log("[+] HttpURLConnection Hook设置成功");
    } catch(e) {
        console.log("[-] HttpURLConnection Hook失败: " + e);
    }
    
    // 2. Hook OkHttp (如果应用使用OkHttp)
    try {
        console.log("[*] 设置OkHttp Hook...");
        
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            OkHttpClient.newCall.implementation = function(request) {
                try {
                    var url = request.url().toString();
                    if (isACBDomain(url)) {
                        console.log("[+] ACB OkHttp请求: " + url);
                        console.log("    方法: " + request.method());
                        
                        // 尝试获取请求头
                        var headers = request.headers();
                        if (headers) {
                            console.log("    请求头:");
                            for (var i = 0; i < headers.size(); i++) {
                                var name = headers.name(i);
                                var value = headers.value(i);
                                console.log("      " + name + ": " + value);
                            }
                        }
                        
                        // 尝试获取请求体
                        var body = request.body();
                        if (body) {
                            console.log("    有请求体");
                        }
                    }
                } catch(e) {
                    // 忽略错误
                }
                
                var result = this.newCall(request);
                return result;
            };
        }
        
        var Response = Java.use("okhttp3.Response");
        if (Response) {
            Response.body.implementation = function() {
                var result = this.body();
                try {
                    var request = this.request();
                    var url = request.url().toString();
                    if (isACBDomain(url)) {
                        console.log("[+] ACB OkHttp响应体获取: " + url);
                        console.log("    状态码: " + this.code());
                    }
                } catch(e) {
                    // 忽略错误
                }
                return result;
            };
        }
        
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        if (ResponseBody) {
            ResponseBody.string.implementation = function() {
                var result = this.string();
                console.log("[+] OkHttp响应体内容: " + result.substring(0, 200) + "...");
                return result;
            };
        }
        
        console.log("[+] OkHttp Hook设置成功");
    } catch(e) {
        console.log("[-] OkHttp Hook失败: " + e);
    }
    
    // 3. Hook JSON解析 (捕获应用层数据)
    try {
        console.log("[*] 设置JSON解析Hook...");
        
        var JSONObject = Java.use("org.json.JSONObject");
        if (JSONObject) {
            JSONObject.$init.overload('java.lang.String').implementation = function(json) {
                console.log("[+] JSON解析: " + json.substring(0, 200) + "...");
                return this.$init(json);
            };
        }
        
        var Gson = Java.use("com.google.gson.Gson");
        if (Gson) {
            Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function(json, classOfT) {
                console.log("[+] Gson解析: " + json.substring(0, 200) + "...");
                console.log("    类型: " + classOfT.getName());
                return this.fromJson(json, classOfT);
            };
        }
        
        console.log("[+] JSON解析Hook设置成功");
    } catch(e) {
        console.log("[-] JSON解析Hook失败: " + e);
    }
    
    // 4. Hook InputStream读取 (尝试捕获解密后的数据)
    try {
        console.log("[*] 设置InputStream Hook...");
        
        var InputStream = Java.use("java.io.InputStream");
        
        InputStream.read.overload('[B').implementation = function(buffer) {
            var result = this.read(buffer);
            if (result > 0) {
                try {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var strData = bytesToString(data);
                    
                    // 检查是否是HTTP响应或包含ACB相关数据
                    if (strData.indexOf("HTTP/") === 0 || 
                        strData.indexOf("GET ") === 0 || 
                        strData.indexOf("POST ") === 0 ||
                        strData.indexOf("Content-Type:") !== -1 ||
                        strData.indexOf("Content-Length:") !== -1 ||
                        strData.indexOf("acb.com") !== -1 ||
                        strData.indexOf("ACB") !== -1 ||
                        strData.indexOf("login") !== -1 ||
                        strData.indexOf("auth") !== -1) {
                        
                        console.log("[+] 可能的ACB HTTP数据读取: " + result + " bytes");
                        console.log("    数据: " + strData);
                        console.log("    十六进制: " + hexData);
                    }
                } catch(e) {
                    // 忽略错误
                }
            }
            return result;
        };
        
        console.log("[+] InputStream Hook设置成功");
    } catch(e) {
        console.log("[-] InputStream Hook失败: " + e);
    }
    
    // 5. Hook 应用特定的网络处理类
    try {
        console.log("[*] 尝试Hook ACB应用特定的网络类...");
        
        var acbClasses = [
            "com.acb.mobile.network.NetworkManager",
            "com.acb.mobile.network.ApiService", 
            "com.acb.mobile.network.HttpClient",
            "com.acb.mobile.network.RequestHandler",
            "com.acb.mobile.network.ResponseHandler",
            "com.acb.mobile.network.DataProcessor",
            "com.acb.mobile.network.JsonParser",
            "com.acb.mobile.network.NetworkCallback",
            "com.acb.mobile.network.SocketManager",
            "com.acb.mobile.network.SocketClient",
            "com.acb.mobile.network.LoginService",
            "com.acb.mobile.network.AuthService",
            "com.acb.mobile.network.UserService"
        ];
        
        acbClasses.forEach(function(className) {
            try {
                var cls = Java.use(className);
                if (cls) {
                    console.log("[+] 找到ACB网络类: " + className);
                    
                    // 尝试Hook一些常见的方法名
                    var commonMethods = ["onResponse", "onSuccess", "onError", "parseResponse", "handleData", "processData", "send", "receive", "login", "authenticate"];
                    commonMethods.forEach(function(methodName) {
                        try {
                            if (cls[methodName]) {
                                console.log("[+] Hook ACB方法: " + className + "." + methodName);
                            }
                        } catch(e) {
                            // 忽略方法不存在的情况
                        }
                    });
                }
            } catch(e) {
                // 忽略类不存在的情况
            }
        });
        
        console.log("[+] ACB应用特定类Hook完成");
    } catch(e) {
        console.log("[-] ACB应用特定类Hook失败: " + e);
    }
    
    // 6. Hook Socket连接 (保持原有的Socket监控)
    try {
        console.log("[*] 设置Java Socket Hook...");
        
        var Socket = Java.use("java.net.Socket");
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            if (isACBDomain(host)) {
                console.log("[+] ACB Socket连接: " + host + ":" + port);
            }
            return result;
        };
        
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            var result = this.connect(endpoint, timeout);
            try {
                var host = this.getInetAddress().getHostName();
                if (isACBDomain(host)) {
                    console.log("[+] ACB Socket连接(带超时): " + host + ":" + this.getPort() + ", 超时: " + timeout);
                }
            } catch(e) {
                // 忽略错误
            }
            return result;
        };
        
        console.log("[+] Java Socket Hook设置成功");
    } catch(e) {
        console.log("[-] Java Socket Hook失败: " + e);
    }
    
    // 7. Hook SSL/TLS底层函数
    try {
        console.log("[*] 设置SSL/TLS底层函数Hook...");
        
        // Hook SSL_write
        var sslWritePtr = Module.findExportByName(null, 'SSL_write');
        if (sslWritePtr) {
            Interceptor.attach(sslWritePtr, {
                onEnter: function(args) {
                    try {
                        var len = args[2].toInt32();
                        if (len > 0 && len < 10000) {
                            var data = Memory.readByteArray(args[1], len);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            
                            // 检查是否包含ACB域名或登录相关数据
                            if (stringData.indexOf("acb.com") !== -1 || 
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("Host:") !== -1 ||
                                stringData.indexOf("login") !== -1 ||
                                stringData.indexOf("auth") !== -1 ||
                                stringData.indexOf("password") !== -1 ||
                                stringData.indexOf("username") !== -1) {
                                
                                console.log("[+] ACB SSL写入: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
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
                        if (len > 0 && len < 10000) {
                            var data = Memory.readByteArray(args[1], len);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            
                            // 检查是否包含ACB相关数据
                            if (stringData.indexOf("acb.com") !== -1 || 
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("HTTP/") === 0 ||
                                stringData.indexOf("Content-Type:") !== -1 ||
                                stringData.indexOf("login") !== -1 ||
                                stringData.indexOf("auth") !== -1) {
                                
                                console.log("[+] ACB SSL读取: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
            });
        }
        
        console.log("[+] SSL/TLS底层函数Hook设置成功");
    } catch(e) {
        console.log("[-] SSL/TLS底层函数Hook失败: " + e);
    }
    
    console.log("[+] 所有ACB全面网络监控Hook已设置完成");
    console.log("[*] 开始监控ACB网络通信...");
    console.log("[*] 监控内容:");
    console.log("    - ACB域名Socket连接");
    console.log("    - HttpURLConnection请求");
    console.log("    - OkHttp请求和响应");
    console.log("    - JSON数据解析");
    console.log("    - SSL/TLS数据");
    console.log("    - 应用层数据处理");
    console.log("[*] 现在请尝试登录操作...");
});

// 数据转换函数
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