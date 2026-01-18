/*
 * TLS解密监控脚本
 * 尝试在TLS解密后捕获明文数据
 */

console.log("[+] TLS解密监控脚本已启动");

Java.perform(function() {
    console.log("[*] TLS解密监控脚本初始化...");
    
    // 1. Hook HttpURLConnection (可能在TLS解密后处理数据)
    try {
        console.log("[*] 设置HttpURLConnection Hook...");
        
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        // Hook getInputStream
        HttpURLConnection.getInputStream.implementation = function() {
            var result = this.getInputStream();
            console.log("[+] HttpURLConnection.getInputStream() 被调用");
            console.log("    URL: " + this.getURL().toString());
            console.log("    Method: " + this.getRequestMethod());
            return result;
        };
        
        // Hook getOutputStream
        HttpURLConnection.getOutputStream.implementation = function() {
            var result = this.getOutputStream();
            console.log("[+] HttpURLConnection.getOutputStream() 被调用");
            console.log("    URL: " + this.getURL().toString());
            console.log("    Method: " + this.getRequestMethod());
            return result;
        };
        
        console.log("[+] HttpURLConnection Hook设置成功");
    } catch(e) {
        console.log("[-] HttpURLConnection Hook失败: " + e);
    }
    
    // 2. Hook InputStream读取 (尝试捕获解密后的数据)
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
                    
                    // 检查是否是HTTP响应
                    if (strData.indexOf("HTTP/") === 0 || 
                        strData.indexOf("GET ") === 0 || 
                        strData.indexOf("POST ") === 0 ||
                        strData.indexOf("Content-Type:") !== -1 ||
                        strData.indexOf("Content-Length:") !== -1) {
                        
                        console.log("[+] 可能的HTTP明文数据读取: " + result + " bytes");
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
    
    // 3. Hook OkHttp (如果应用使用OkHttp)
    try {
        console.log("[*] 设置OkHttp Hook...");
        
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            OkHttpClient.newCall.implementation = function(request) {
                console.log("[+] OkHttp请求: " + request.url().toString());
                console.log("    方法: " + request.method());
                
                var result = this.newCall(request);
                return result;
            };
        }
        
        var Response = Java.use("okhttp3.Response");
        if (Response) {
            Response.body.implementation = function() {
                var result = this.body();
                console.log("[+] OkHttp响应体获取");
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
    
    // 4. Hook JSON解析 (捕获应用层数据)
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
    
    // 5. Hook 应用特定的网络处理类
    try {
        console.log("[*] 尝试Hook应用特定的网络类...");
        
        var classesToTry = [
            "com.acb.mobile.network.NetworkManager",
            "com.acb.mobile.network.ApiService",
            "com.acb.mobile.network.HttpClient",
            "com.acb.mobile.network.RequestHandler",
            "com.acb.mobile.network.ResponseHandler",
            "com.acb.mobile.network.DataProcessor",
            "com.acb.mobile.network.JsonParser",
            "com.acb.mobile.network.NetworkCallback"
        ];
        
        classesToTry.forEach(function(className) {
            try {
                var cls = Java.use(className);
                if (cls) {
                    console.log("[+] 找到应用特定类: " + className);
                    
                    // 尝试Hook所有方法
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        try {
                            var methodName = method.getName();
                            if (methodName.indexOf("onResponse") !== -1 || 
                                methodName.indexOf("onSuccess") !== -1 ||
                                methodName.indexOf("parseResponse") !== -1 ||
                                methodName.indexOf("handleData") !== -1 ||
                                methodName.indexOf("processData") !== -1) {
                                
                                console.log("[+] Hook方法: " + className + "." + methodName);
                                
                                // 这里可以添加具体的方法Hook逻辑
                            }
                        } catch(e) {
                            // 忽略单个方法Hook失败
                        }
                    });
                }
            } catch(e) {
                // 忽略类不存在的情况
            }
        });
        
        console.log("[+] 应用特定类Hook完成");
    } catch(e) {
        console.log("[-] 应用特定类Hook失败: " + e);
    }
    
    console.log("[+] 所有TLS解密监控Hook已设置完成");
    console.log("[*] 开始监控解密后的数据...");
});

// 辅助函数
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