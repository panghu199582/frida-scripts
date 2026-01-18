Java.perform(function() {
    console.log("[*] Starting enhanced request monitoring...");
    
    // 监控OkHttp请求
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.implementation = function(request) {
        console.log('\n[+] New Request Detected:');
        console.log('[+] URL:', request.url().toString());
        console.log('[+] Method:', request.method());
        
        // 获取请求头
        var headers = request.headers();
        console.log('[+] Headers:');
        for (var i = 0; i < headers.size(); i++) {
            console.log('    ' + headers.name(i) + ': ' + headers.value(i));
        }
        
        // 获取请求体
        var requestBody = request.body();
        if (requestBody) {
            var Buffer = Java.use('okio.Buffer');
            var buffer = Buffer.$new();
            requestBody.writeTo(buffer);
            console.log('[+] Request Body:', buffer.readUtf8());
        }
        
        // 获取响应
        var call = this.newCall(request);
        call.enqueue.implementation = function(callback) {
            console.log('[+] Request enqueued');
            var originalCallback = callback;
            var WrapperCallback = Java.registerClass({
                name: 'okhttp3.CallbackWrapper',
                implements: [Java.use('okhttp3.Callback')],
                methods: {
                    onFailure: function(call, e) {
                        console.log('[+] Request failed:', e);
                        originalCallback.onFailure(call, e);
                    },
                    onResponse: function(call, response) {
                        console.log('[+] Response received');
                        console.log('[+] Response code:', response.code());
                        
                        // 获取响应头
                        var responseHeaders = response.headers();
                        console.log('[+] Response Headers:');
                        for (var i = 0; i < responseHeaders.size(); i++) {
                            console.log('    ' + responseHeaders.name(i) + ': ' + responseHeaders.value(i));
                        }
                        
                        // 获取响应体
                        var responseBody = response.body();
                        if (responseBody) {
                            var bodyString = responseBody.string();
                            console.log('[+] Response Body:', bodyString);
                            
                            // 重新构建ResponseBody，因为string()方法会消耗流
                            var MediaType = Java.use('okhttp3.MediaType');
                            var ResponseBody = Java.use('okhttp3.ResponseBody');
                            var newBody = ResponseBody.create(responseBody.contentType(), bodyString);
                            
                            // 创建新的Response对象
                            var newResponse = response.newBuilder()
                                .body(newBody)
                                .build();
                                
                            originalCallback.onResponse(call, newResponse);
                        } else {
                            originalCallback.onResponse(call, response);
                        }
                    }
                }
            });
            
            call.enqueue(WrapperCallback.$new());
        };
        
        return call;
    };
    
    // 监控SSL/TLS
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.implementation = function(keyManagers, trustManagers, secureRandom) {
        console.log('\n[+] SSLContext.init called');
        if (keyManagers) {
            console.log('[+] KeyManagers present');
            for (var i = 0; i < keyManagers.length; i++) {
                console.log('    KeyManager[' + i + ']:', keyManagers[i]);
            }
        }
        if (trustManagers) {
            console.log('[+] TrustManagers present');
            for (var i = 0; i < trustManagers.length; i++) {
                console.log('    TrustManager[' + i + ']:', trustManagers[i]);
            }
        }
        this.init(keyManagers, trustManagers, secureRandom);
    };

    // 监控证书验证
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log('[+] checkServerTrusted called');
        console.log('[+] Certificate chain:', chain);
        console.log('[+] Auth type:', authType);
        return this.checkServerTrusted(chain, authType);
    };
});


Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.includes("su")) {
            console.log("[Blocked] su command: " + cmd);
            return null; // 返回空，模拟执行失败
        }
        return this.exec(cmd);
    };
});