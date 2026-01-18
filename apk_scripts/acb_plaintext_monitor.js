/*
 * ACB明文数据监控脚本
 * 尝试在TLS解密后捕获明文数据
 */

console.log("[+] ACB明文数据监控脚本已启动");

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
    console.log("[*] ACB明文数据监控脚本初始化...");
    console.log("[*] 监控的ACB域名: " + ACB_DOMAINS.join(", "));
    
    // 1. Hook HttpURLConnection (应用层HTTP)
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
                    
                    // Hook这个InputStream来读取响应数据
                    var originalInputStream = result;
                    var hookedInputStream = Java.use("java.io.InputStream").$new();
                    
                    // 替换read方法
                    hookedInputStream.read.overload('[B').implementation = function(buffer) {
                        var bytesRead = originalInputStream.read(buffer);
                        if (bytesRead > 0) {
                            try {
                                var data = Java.array('byte', buffer);
                                var strData = bytesToString(data);
                                console.log("[+] ACB HttpURLConnection响应: " + bytesRead + " bytes");
                                console.log("    数据: " + strData);
                            } catch(e) {
                                // 忽略错误
                            }
                        }
                        return bytesRead;
                    };
                    
                    return hookedInputStream;
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
                    
                    // Hook这个OutputStream来写入请求数据
                    var originalOutputStream = result;
                    var hookedOutputStream = Java.use("java.io.OutputStream").$new();
                    
                    // 替换write方法
                    hookedOutputStream.write.overload('[B').implementation = function(buffer) {
                        try {
                            var data = Java.array('byte', buffer);
                            var strData = bytesToString(data);
                            console.log("[+] ACB HttpURLConnection请求: " + data.length + " bytes");
                            console.log("    数据: " + strData);
                        } catch(e) {
                            // 忽略错误
                        }
                        return originalOutputStream.write(buffer);
                    };
                    
                    return hookedOutputStream;
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
                            
                            // Hook请求体写入
                            var RequestBody = Java.use("okhttp3.RequestBody");
                            if (RequestBody) {
                                RequestBody.writeTo.implementation = function(sink) {
                                    console.log("[+] OkHttp请求体写入");
                                    return this.writeTo(sink);
                                };
                            }
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
                console.log("[+] OkHttp响应体内容: " + result.substring(0, 500) + "...");
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
                console.log("[+] JSON解析: " + json.substring(0, 500) + "...");
                return this.$init(json);
            };
        }
        
        var Gson = Java.use("com.google.gson.Gson");
        if (Gson) {
            Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function(json, classOfT) {
                console.log("[+] Gson解析: " + json.substring(0, 500) + "...");
                console.log("    类型: " + classOfT.getName());
                return this.fromJson(json, classOfT);
            };
        }
        
        console.log("[+] JSON解析Hook设置成功");
    } catch(e) {
        console.log("[-] JSON解析Hook失败: " + e);
    }
    
    // 4. Hook BufferedReader (读取HTTP响应)
    try {
        console.log("[*] 设置BufferedReader Hook...");
        
        var BufferedReader = Java.use("java.io.BufferedReader");
        if (BufferedReader) {
            BufferedReader.readLine.implementation = function() {
                var result = this.readLine();
                if (result) {
                    // 检查是否包含ACB相关数据
                    if (result.indexOf("acb.com") !== -1 || 
                        result.indexOf("ACB") !== -1 ||
                        result.indexOf("HTTP/") === 0 ||
                        result.indexOf("Content-Type:") !== -1 ||
                        result.indexOf("Content-Length:") !== -1 ||
                        result.indexOf("login") !== -1 ||
                        result.indexOf("auth") !== -1 ||
                        result.indexOf("{") !== -1) {
                        
                        console.log("[+] BufferedReader读取: " + result);
                    }
                }
                return result;
            };
        }
        
        console.log("[+] BufferedReader Hook设置成功");
    } catch(e) {
        console.log("[-] BufferedReader Hook失败: " + e);
    }
    
    // 5. Hook PrintWriter (写入HTTP请求)
    try {
        console.log("[*] 设置PrintWriter Hook...");
        
        var PrintWriter = Java.use("java.io.PrintWriter");
        if (PrintWriter) {
            PrintWriter.println.overload('java.lang.String').implementation = function(str) {
                if (str && (str.indexOf("acb.com") !== -1 || 
                           str.indexOf("ACB") !== -1 ||
                           str.indexOf("login") !== -1 ||
                           str.indexOf("auth") !== -1 ||
                           str.indexOf("{") !== -1)) {
                    console.log("[+] PrintWriter写入: " + str);
                }
                return this.println(str);
            };
        }
        
        console.log("[+] PrintWriter Hook设置成功");
    } catch(e) {
        console.log("[-] PrintWriter Hook失败: " + e);
    }
    
    // 6. Hook 应用特定的网络处理类
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
            "com.acb.mobile.network.UserService",
            "com.acb.mobile.network.ApiManager",
            "com.acb.mobile.network.RestClient"
        ];
        
        acbClasses.forEach(function(className) {
            try {
                var cls = Java.use(className);
                if (cls) {
                    console.log("[+] 找到ACB网络类: " + className);
                    
                    // 尝试Hook一些常见的方法名
                    var commonMethods = ["onResponse", "onSuccess", "onError", "parseResponse", "handleData", "processData", "send", "receive", "login", "authenticate", "post", "get"];
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
    
    console.log("[+] 所有ACB明文数据监控Hook已设置完成");
    console.log("[*] 开始监控ACB明文数据...");
    console.log("[*] 监控内容:");
    console.log("    - HttpURLConnection请求和响应");
    console.log("    - OkHttp请求和响应");
    console.log("    - JSON数据解析");
    console.log("    - BufferedReader读取");
    console.log("    - PrintWriter写入");
    console.log("    - 应用层数据处理");
    console.log("[*] 现在请尝试登录操作...");
});

// 数据转换函数
function bytesToString(bytes) {
    if (!bytes || bytes.length === 0) return "";
    var str = "";
    for (var i = 0; i < Math.min(bytes.length, 200); i++) {
        var b = bytes[i] & 0xff;
        if (b >= 32 && b <= 126) {
            str += String.fromCharCode(b);
        } else {
            str += ".";
        }
    }
    if (bytes.length > 200) str += "...";
    return str;
} 