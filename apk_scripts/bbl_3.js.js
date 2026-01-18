// 添加一个全局的日志函数
function log(message) {
    try {
        console.log("[BBL_DEBUG] " + message);
        Java.perform(function() {
            var Log = Java.use("android.util.Log");
            Log.d("BBL_DEBUG", message);
        });
    } catch(e) {
        console.log("[BBL_ERROR] Failed to log: " + e);
    }
}

// 在脚本开始时输出标记
log("=== BBL JSHook Script Started ===");

// 添加错误处理
try {
    Java.perform(function() {
        log("Script started");

        // 检查进程名
        var Process = Java.use("android.os.Process");
        var currentPid = Process.myPid();
        log("Current process ID: " + currentPid);

        // 检查包名
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();
        var packageName = context.getPackageName();
        log("Current package name: " + packageName);

        // 1. OkHttp
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            log("Found OkHttpClient class");
            
            OkHttpClient.newCall.implementation = function(request) {
                try {
                    var url = request.url().toString();
                    log("\n[阶段1: 请求发送] ==========================================");
                    log("时间: " + new Date().toLocaleString());
                    log("URL: " + url);
                    log("Method: " + request.method());
                    
                    // 打印所有请求头
                    var headers = request.headers();
                    log("\n[请求头信息]");
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        log(name + ": " + value);
                    }
                    
                    // 检查请求体
                    var body = request.body();
                    if (body) {
                        try {
                            var buffer = Java.use("okio.Buffer").$new();
                            body.writeTo(buffer);
                            var bodyString = buffer.readUtf8();
                            log("\n[请求体信息]");
                            log("原始数据: " + bodyString);
                            
                            // 如果是JSON，尝试格式化输出
                            try {
                                var jsonBody = JSON.parse(bodyString);
                                log("\n[请求体JSON格式化]");
                                log(JSON.stringify(jsonBody, null, 2));
                            } catch(e) {
                                // 不是JSON格式，忽略错误
                            }
                        } catch(e) {
                            log("读取请求体失败: " + e);
                        }
                    }

                    // 获取响应
                    var call = this.newCall(request);
                    var response = call.execute();
                    log("\n[响应信息]");
                    log("状态码: " + response.code());
                    
                    // 打印响应头
                    var responseHeaders = response.headers();
                    log("\n[响应头信息]");
                    for (var i = 0; i < responseHeaders.size(); i++) {
                        var name = responseHeaders.name(i);
                        var value = responseHeaders.value(i);
                        log(name + ": " + value);
                    }
                    
                    // 打印响应体
                    var responseBody = response.body();
                    if (responseBody) {
                        var responseString = responseBody.string();
                        log("\n[响应体信息]");
                        log(responseString);
                        
                        // 重新创建ResponseBody
                        var MediaType = Java.use("okhttp3.MediaType");
                        var ResponseBody = Java.use("okhttp3.ResponseBody");
                        var newBody = ResponseBody.create(responseBody.contentType(), responseString);
                        response = response.newBuilder().body(newBody).build();
                    }
                    
                    log("\n[阶段1: 请求发送完成] ======================================");
                    return response;
                } catch(e) {
                    log("请求处理错误: " + e);
                    return this.newCall(request);
                }
            };
            log("OkHttp hook 安装完成");
        } catch(e) {
            log("OkHttp hook 安装失败: " + e);
        }

        // 2. HttpURLConnection
        // try {
        //     var URL = Java.use("java.net.URL");
        //     log("Found URL class");
            
        //     URL.openConnection.overload().implementation = function() {
        //         try {
        //             var connection = this.openConnection();
        //             log("URL Connection: " + this.toString());
        //             log("Connection type: " + connection.$className);
        //             return connection;
        //         } catch(e) {
        //             log("Error in URL hook: " + e);
        //             return this.openConnection();
        //         }
        //     };
        //     log("HttpURLConnection hook installed");
        // } catch(e) {
        //     log("HttpURLConnection hook failed: " + e);
        // }

        // 3. Volley
        // try {
        //     var RequestQueue = Java.use("com.android.volley.RequestQueue");
        //     var Request = Java.use("com.android.volley.Request");
            
        //     RequestQueue.add.implementation = function(request) {
        //         log("Volley Request: " + request.getUrl());
        //         log("Method: " + request.getMethod());
        //         log("Headers: " + request.getHeaders().toString());
        //         return this.add(request);
        //     };
        //     log("Volley hook installed");
        // } catch(e) {
        //     log("Volley hook failed: " + e);
        // }

        // 4. Retrofit
        // try {
        //     var Retrofit = Java.use("retrofit2.Retrofit");
        //     var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            
        //     Retrofit.create.implementation = function(serviceClass) {
        //         log("Retrofit Service: " + serviceClass.getName());
        //         return this.create(serviceClass);
        //     };
        //     log("Retrofit hook installed");
        // } catch(e) {
        //     log("Retrofit hook failed: " + e);
        // }

        // // 5. WebView
        // try {
        //     var WebView = Java.use("android.webkit.WebView");
        //     var WebViewClient = Java.use("android.webkit.WebViewClient");
            
        //     WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        //         log("WebView loadUrl: " + url);
        //         return this.loadUrl(url);
        //     };
            
        //     WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
        //         log("WebView loadUrl with headers: " + url);
        //         log("Headers: " + headers.toString());
        //         return this.loadUrl(url, headers);
        //     };
        //     log("WebView hook installed");
        // } catch(e) {
        //     log("WebView hook failed: " + e);
        // }

        // 6. Socket
        // try {
        //     var Socket = Java.use("java.net.Socket");
        //     var OutputStream = Java.use("java.io.OutputStream");
        //     var InputStream = Java.use("java.io.InputStream");
            
        //     Socket.getOutputStream.implementation = function() {
        //         log("Socket OutputStream: " + this.getInetAddress().toString() + ":" + this.getPort());
        //         return this.getOutputStream();
        //     };
            
        //     Socket.getInputStream.implementation = function() {
        //         log("Socket InputStream: " + this.getInetAddress().toString() + ":" + this.getPort());
        //         return this.getInputStream();
        //     };
        //     log("Socket hook installed");
        // } catch(e) {
        //     log("Socket hook failed: " + e);
        // }

        // // 7. SSLSocket
        // try {
        //     var SSLSocket = Java.use("javax.net.ssl.SSLSocket");
            
        //     SSLSocket.getOutputStream.implementation = function() {
        //         // log("SSLSocket OutputStream: " + this.getInetAddress().toString() + ":" + this.getPort());
        //         return this.getOutputStream();
        //     };
            
        //     SSLSocket.getInputStream.implementation = function() {
        //         // log("SSLSocket InputStream: " + this.getInetAddress().toString() + ":" + this.getPort());
        //         return this.getInputStream();
        //     };
        //     log("SSLSocket hook installed");
        // } catch(e) {
        //     log("SSLSocket hook failed: " + e);
        // }

        // 8. URLConnection
        try {
            var URLConnection = Java.use("java.net.URLConnection");
            
            URLConnection.getInputStream.implementation = function() {
                log("URLConnection Request: " + this.getURL().toString());
                log("Method: " + this.getRequestMethod());
                log("Headers: " + this.getRequestProperties().toString());
                return this.getInputStream();
            };
            log("URLConnection hook installed");
        } catch(e) {
            log("URLConnection hook failed: " + e);
        }

        // 9. HttpsURLConnection
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            
            HttpsURLConnection.getInputStream.implementation = function() {
                log("HttpsURLConnection Request: " + this.getURL().toString());
                log("Method: " + this.getRequestMethod());
                log("Headers: " + this.getRequestProperties().toString());
                return this.getInputStream();
            };
            log("HttpsURLConnection hook installed");
        } catch(e) {
            log("HttpsURLConnection hook failed: " + e);
        }

        // 10. WebSocket
        try {
            var WebSocket = Java.use("okhttp3.WebSocket");
            var WebSocketListener = Java.use("okhttp3.WebSocketListener");
            
            WebSocket.send.overload('java.lang.String').implementation = function(text) {
                log("WebSocket send text: " + text);
                return this.send(text);
            };
            
            WebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
                log("WebSocket send bytes: " + bytes.hex());
                return this.send(bytes);
            };
            log("WebSocket hook installed");
        } catch(e) {
            log("WebSocket hook failed: " + e);
        }

        // Hook Request.Builder
        try {
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            RequestBuilder.build.implementation = function() {
                var request = this.build();
                var url = request.url().toString();
                
                if (url.includes('/api/v3/authentication/pin')) {
                    log("\n[阶段2: 请求构建] ==========================================");
                    log("时间: " + new Date().toLocaleString());
                    log("URL: " + url);
                    log("Method: " + request.method());
                    
                    // 打印请求头
                    var headers = request.headers();
                    log("\n[请求头信息]");
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        log(name + ": " + value);
                    }
                    
                    // 打印请求体
                    var body = request.body();
                    if (body) {
                        try {
                            var buffer = Java.use("okio.Buffer").$new();
                            body.writeTo(buffer);
                            var bodyString = buffer.readUtf8();
                            log("\n[请求体信息]");
                            log("原始数据: " + bodyString);
                            
                            // 如果是JSON，尝试格式化输出
                            try {
                                var jsonBody = JSON.parse(bodyString);
                                log("\n[请求体JSON格式化]");
                                log(JSON.stringify(jsonBody, null, 2));
                            } catch(e) {
                                // 不是JSON格式，忽略错误
                            }
                        } catch(e) {
                            log("读取请求体失败: " + e);
                        }
                    }
                    
                    log("\n[阶段2: 请求构建完成] ======================================");
                }
                
                return request;
            };
            log("Request.Builder hook 安装完成");
        } catch(e) {
            log("Request.Builder hook 安装失败: " + e);
        }

        // 心跳日志
        setInterval(function() {
            // log("Script is still running...");
        }, 5000);

        log("All hooks installed successfully");
    });
} catch(e) {
    log("Fatal error in script: " + e);
} 