Java.perform(function() {
    console.log("[+] OkHttp3 & Okio Network Capture Script Loaded");
    
    // Helper function to convert byte array to hex string
    function bytes2hex(bytes) {
        var result = '';
        for (var i = 0; i < bytes.length; i++) {
            var hex = (bytes[i] & 0xFF).toString(16);
            if (hex.length === 1) {
                hex = '0' + hex;
            }
            result += hex;
        }
        return result;
    }

    try {
        var realCall = Java.use("okhttp3.internal.connection.RealCall");
        realCall.execute.implementation = function() {
            console.log("[+] RealCall.execute() called");
            var result = this.execute();
            // console.log("[+] RealCall.execute() result: " + result.toString());
            console.log("[+] RealCall URL: " + result.request().url().toString());
            console.log("[+]          Method: " + result.request().method());
            
            // 常规打印请求body
            try {
                var requestBody = result.request().body();
                if (requestBody != null) {
                    // 打印类型和长度
                    console.log("[+]          Request Body Type: " + requestBody.contentType());
                    console.log("[+]          Request Body Length: " + requestBody.contentLength());
            
                    // 用 okio.Buffer 读取内容
                    var Buffer = Java.use("okio.Buffer");
                    var buffer = Buffer.$new();
                    requestBody.writeTo(buffer);
            
                    // 优先尝试以字符串打印
                    try {
                        var bodyString = buffer.readUtf8();
                        console.log("[+]          Request Body Content: " + bodyString);
                    } catch (e) {
                        // 如果不是文本，打印十六进制
                        buffer.reset();
                        var bytes = buffer.readByteArray();
                        console.log("[+]          Request Body Content (Hex): " + bytes2hex(bytes));
                    }
                } else {
                    console.log("[+]          Request Body: null");
                }
            } catch (e) {
                console.log("[-] Error reading request body: " + e);
            }
            
            console.log("[+]          Request Headers: " + result.request().headers().size());
            if(result.request().headers().size() > 0) {
                for (var i = 0; i < result.request().headers().size(); i++) {
                    console.log("       Request Headers: " + result.request().headers().name(i) + ": " + result.request().headers().value(i));
                }
            }
            
            if(result.headers().size() > 0) {
                for (var i = 0; i < result.headers().size(); i++) {
                    console.log("       Response Headers: " + result.headers().name(i) + ": " + result.headers().value(i));
                }
            }
            
            // 打印响应体
            // try {
            //     var responseBody = result.body();
            //     if(responseBody != null) {
            //         console.log("[+] Response Body Type: " + responseBody.contentType());
            //         console.log("[+] Response Body Length: " + responseBody.contentLength());
                    
            //         // 检查响应体是否支持peekBody方法
            //         if (responseBody.peekBody && typeof responseBody.peekBody === 'function') {
            //             try {
            //                 var maxLength = 1024 * 1024; // 1MB限制
            //                 var peekBody = responseBody.peekBody(maxLength);
                            
            //                 if (peekBody.string && typeof peekBody.string === 'function') {
            //                     var bodyString = peekBody.string();
            //                     console.log("[+] RealCall Response Body: " + bodyString);
            //                 } else if (peekBody.bytes && typeof peekBody.bytes === 'function') {
            //                     var bytes = peekBody.bytes();
            //                     console.log("[+] RealCall Response Body (Hex): " + bytes2hex(bytes));
            //                 }
            //             } catch (e) {
            //                 console.log("[-] peekBody failed: " + e);
            //             }
            //         } else {
            //             // 如果peekBody不可用，尝试直接读取（可能会消耗流）
            //             try {
            //                 if (responseBody.string && typeof responseBody.string === 'function') {
            //                     var bodyString = responseBody.string();
            //                     console.log("[+] RealCall Response Body: " + bodyString);
            //                 } else if (responseBody.bytes && typeof responseBody.bytes === 'function') {
            //                     var bytes = responseBody.bytes();
            //                     console.log("[+] RealCall Response Body (Hex): " + bytes2hex(bytes));
            //                 } else if (responseBody.source && typeof responseBody.source === 'function') {
            //                     // 使用source方法读取
            //                     var source = responseBody.source();
            //                     var buffer = Java.use("okio.Buffer").$new();
            //                     buffer.writeAll(source);
            //                     var bodyString = buffer.readUtf8();
            //                     console.log("[+] RealCall Response Body: " + bodyString);
            //                 }
            //             } catch (e) {
            //                 console.log("[-] Direct body reading failed: " + e);
            //             }
            //         }
            //     } else {
            //         console.log("[+] Response Body is null");
            //     }
            // } catch (e) {
            //     console.log("[-] Error reading response body: " + e);
            // }
            
            console.log("[+] RealCall.execute() completed");
            // return result.response();
            return result;
        };  
        realCall.enqueue.implementation = function(callback) {
            console.log("[+] RealCall.enqueue() called");
            var result = this.enqueue(callback);
            console.log("[+] RealCall.enqueue() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] RealCall not found: " + e);
    }
    
    
    
    
    
    
    console.log("[+] OkHttp3 & Okio capture hooks installed successfully");
    console.log("[+] Monitoring all modern network library activity...");
}); 