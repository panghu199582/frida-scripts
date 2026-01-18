console.log("[*] 开始监控iOS网络请求...");

// 存储捕获的网络请求
var capturedRequests = [];
var capturedResponses = [];

// 监控NSURLSession
try {
    // 监控NSURLSession dataTaskWithRequest
    Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLSession dataTaskWithRequest:completionHandler: 被调用");
            this.request = args[1];
            
            var url = ObjC.classes.NSURLRequest.instanceMethod_URL_(this.request);
            var method = ObjC.classes.NSURLRequest.instanceMethod_HTTPMethod_(this.request);
            var headers = ObjC.classes.NSURLRequest.instanceMethod_allHTTPHeaderFields_(this.request);
            var body = ObjC.classes.NSURLRequest.instanceMethod_HTTPBody_(this.request);
            
            console.log("    URL: " + ObjC.Object(url).toString());
            console.log("    方法: " + ObjC.Object(method).toString());
            
            if (headers) {
                console.log("    头部:");
                var keys = ObjC.classes.NSDictionary.instanceMethod_allKeys_(headers);
                var count = ObjC.classes.NSArray.instanceMethod_count_(keys);
                
                for (var i = 0; i < count; i++) {
                    var key = ObjC.classes.NSArray.instanceMethod_objectAtIndex_(keys, i);
                    var value = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(headers, key);
                    console.log("        " + ObjC.Object(key).toString() + ": " + ObjC.Object(value).toString());
                }
            }
            
            if (body) {
                var bodyLength = ObjC.classes.NSData.instanceMethod_getLength_(body);
                console.log("    请求体长度: " + bodyLength);
                
                // 尝试读取请求体
                var bytes = Memory.readByteArray(body, bodyLength);
                console.log("    请求体: " + hexdump(bytes, { length: bodyLength }));
                
                // 尝试解析为字符串
                try {
                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                    console.log("    请求体(字符串): " + str);
                    
                    // 检查是否包含加密数据
                    if (str.includes("encrypt") || str.includes("cipher") || str.includes("key") || 
                        str.includes("iv") || str.includes("nonce") || str.includes("salt")) {
                        console.log("[!] 发现可能的加密数据在请求体中");
                        
                        // 保存请求
                        capturedRequests.push({
                            url: ObjC.Object(url).toString(),
                            method: ObjC.Object(method).toString(),
                            headers: headers ? ObjC.Object(headers).toString() : null,
                            body: str,
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch(e) {
                    console.log("    请求体不是有效的UTF-8字符串");
                    
                    // 检查二进制数据是否可能是加密的
                    var isEncrypted = false;
                    for (var i = 0; i < bodyLength; i++) {
                        var byte = Memory.readU8(body.add(i));
                        // 检查熵值，高熵值通常表示加密数据
                        if (byte === 0 || byte === 255) {
                            isEncrypted = true;
                            break;
                        }
                    }
                    
                    if (isEncrypted) {
                        console.log("[!] 发现可能的加密二进制数据在请求体中");
                        
                        // 保存请求
                        capturedRequests.push({
                            url: ObjC.Object(url).toString(),
                            method: ObjC.Object(method).toString(),
                            headers: headers ? ObjC.Object(headers).toString() : null,
                            bodyHex: hexdump(bytes, { length: bodyLength }),
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSURLSession dataTaskWithRequest:completionHandler:: " + e);
}

// 监控NSURLSession dataTaskWithURL
try {
    Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithURL:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLSession dataTaskWithURL: 被调用");
            this.url = args[1];
            
            console.log("    URL: " + ObjC.Object(this.url).toString());
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSURLSession dataTaskWithURL:: " + e);
}

// 监控NSURLSession dataTaskWithURL completionHandler
try {
    Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithURL:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLSession dataTaskWithURL:completionHandler: 被调用");
            this.url = args[1];
            
            console.log("    URL: " + ObjC.Object(this.url).toString());
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSURLSession dataTaskWithURL:completionHandler:: " + e);
}

// 监控NSURLConnection
try {
    // 监控NSURLConnection sendSynchronousRequest
    Interceptor.attach(ObjC.classes.NSURLConnection["+ sendSynchronousRequest:returningResponse:error:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSURLConnection sendSynchronousRequest:returningResponse:error: 被调用");
            this.request = args[1];
            
            var url = ObjC.classes.NSURLRequest.instanceMethod_URL_(this.request);
            var method = ObjC.classes.NSURLRequest.instanceMethod_HTTPMethod_(this.request);
            var headers = ObjC.classes.NSURLRequest.instanceMethod_allHTTPHeaderFields_(this.request);
            var body = ObjC.classes.NSURLRequest.instanceMethod_HTTPBody_(this.request);
            
            console.log("    URL: " + ObjC.Object(url).toString());
            console.log("    方法: " + ObjC.Object(method).toString());
            
            if (headers) {
                console.log("    头部:");
                var keys = ObjC.classes.NSDictionary.instanceMethod_allKeys_(headers);
                var count = ObjC.classes.NSArray.instanceMethod_count_(keys);
                
                for (var i = 0; i < count; i++) {
                    var key = ObjC.classes.NSArray.instanceMethod_objectAtIndex_(keys, i);
                    var value = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(headers, key);
                    console.log("        " + ObjC.Object(key).toString() + ": " + ObjC.Object(value).toString());
                }
            }
            
            if (body) {
                var bodyLength = ObjC.classes.NSData.instanceMethod_getLength_(body);
                console.log("    请求体长度: " + bodyLength);
                
                // 尝试读取请求体
                var bytes = Memory.readByteArray(body, bodyLength);
                console.log("    请求体: " + hexdump(bytes, { length: bodyLength }));
                
                // 尝试解析为字符串
                try {
                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4).toString();
                    console.log("    请求体(字符串): " + str);
                    
                    // 检查是否包含加密数据
                    if (str.includes("encrypt") || str.includes("cipher") || str.includes("key") || 
                        str.includes("iv") || str.includes("nonce") || str.includes("salt")) {
                        console.log("[!] 发现可能的加密数据在请求体中");
                        
                        // 保存请求
                        capturedRequests.push({
                            url: ObjC.Object(url).toString(),
                            method: ObjC.Object(method).toString(),
                            headers: headers ? ObjC.Object(headers).toString() : null,
                            body: str,
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch(e) {
                    console.log("    请求体不是有效的UTF-8字符串");
                    
                    // 检查二进制数据是否可能是加密的
                    var isEncrypted = false;
                    for (var i = 0; i < bodyLength; i++) {
                        var byte = Memory.readU8(body.add(i));
                        // 检查熵值，高熵值通常表示加密数据
                        if (byte === 0 || byte === 255) {
                            isEncrypted = true;
                            break;
                        }
                    }
                    
                    if (isEncrypted) {
                        console.log("[!] 发现可能的加密二进制数据在请求体中");
                        
                        // 保存请求
                        capturedRequests.push({
                            url: ObjC.Object(url).toString(),
                            method: ObjC.Object(method).toString(),
                            headers: headers ? ObjC.Object(headers).toString() : null,
                            bodyHex: hexdump(bytes, { length: bodyLength }),
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (retval) {
                var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(retval);
                console.log("    响应体长度: " + dataLength);
                
                // 尝试读取响应体
                var bytes = Memory.readByteArray(retval, dataLength);
                console.log("    响应体: " + hexdump(bytes, { length: dataLength }));
                
                // 尝试解析为字符串
                try {
                    var str = ObjC.classes.NSString.alloc().initWithData_encoding_(retval, 4).toString();
                    console.log("    响应体(字符串): " + str);
                    
                    // 检查是否包含加密数据
                    if (str.includes("encrypt") || str.includes("cipher") || str.includes("key") || 
                        str.includes("iv") || str.includes("nonce") || str.includes("salt")) {
                        console.log("[!] 发现可能的加密数据在响应体中");
                        
                        // 保存响应
                        capturedResponses.push({
                            body: str,
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch(e) {
                    console.log("    响应体不是有效的UTF-8字符串");
                    
                    // 检查二进制数据是否可能是加密的
                    var isEncrypted = false;
                    for (var i = 0; i < dataLength; i++) {
                        var byte = Memory.readU8(retval.add(i));
                        // 检查熵值，高熵值通常表示加密数据
                        if (byte === 0 || byte === 255) {
                            isEncrypted = true;
                            break;
                        }
                    }
                    
                    if (isEncrypted) {
                        console.log("[!] 发现可能的加密二进制数据在响应体中");
                        
                        // 保存响应
                        capturedResponses.push({
                            bodyHex: hexdump(bytes, { length: dataLength }),
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSURLConnection sendSynchronousRequest:returningResponse:error:: " + e);
}

// 监控底层网络函数
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
        console.log("[+] send 被调用");
        console.log("    长度: " + this.len);
        console.log("    数据: " + hexdump(this.buf, { length: this.len }));
        
        // 检查数据是否可能是加密的
        var isEncrypted = false;
        for (var i = 0; i < this.len; i++) {
            var byte = Memory.readU8(this.buf.add(i));
            // 检查熵值，高熵值通常表示加密数据
            if (byte === 0 || byte === 255) {
                isEncrypted = true;
                break;
            }
        }
        
        if (isEncrypted) {
            console.log("[!] 发现可能的加密数据在send调用中");
            
            // 保存请求
            capturedRequests.push({
                method: "SOCKET",
                bodyHex: hexdump(this.buf, { length: this.len }),
                timestamp: new Date().toISOString()
            });
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "recv"), {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
        console.log("[+] recv 被调用");
        console.log("    长度: " + this.len);
    },
    onLeave: function(retval) {
        var length = retval.toInt32();
        if (length > 0) {
            console.log("    接收数据: " + hexdump(this.buf, { length: length }));
            
            // 检查数据是否可能是加密的
            var isEncrypted = false;
            for (var i = 0; i < length; i++) {
                var byte = Memory.readU8(this.buf.add(i));
                // 检查熵值，高熵值通常表示加密数据
                if (byte === 0 || byte === 255) {
                    isEncrypted = true;
                    break;
                }
            }
            
            if (isEncrypted) {
                console.log("[!] 发现可能的加密数据在recv调用中");
                
                // 保存响应
                capturedResponses.push({
                    bodyHex: hexdump(this.buf, { length: length }),
                    timestamp: new Date().toISOString()
                });
            }
        }
    }
});

// 添加全局函数来查看捕获的请求和响应
global.showCapturedRequests = function() {
    console.log("[*] 捕获的请求数量: " + capturedRequests.length);
    for (var i = 0; i < capturedRequests.length; i++) {
        console.log("请求 #" + (i+1) + " - " + capturedRequests[i].timestamp);
        console.log("URL: " + capturedRequests[i].url);
        console.log("方法: " + capturedRequests[i].method);
        if (capturedRequests[i].headers) {
            console.log("头部: " + capturedRequests[i].headers);
        }
        if (capturedRequests[i].body) {
            console.log("请求体: " + capturedRequests[i].body);
        }
        if (capturedRequests[i].bodyHex) {
            console.log("请求体(十六进制): " + capturedRequests[i].bodyHex);
        }
        console.log("-----------------------------------");
    }
};

global.showCapturedResponses = function() {
    console.log("[*] 捕获的响应数量: " + capturedResponses.length);
    for (var i = 0; i < capturedResponses.length; i++) {
        console.log("响应 #" + (i+1) + " - " + capturedResponses[i].timestamp);
        if (capturedResponses[i].body) {
            console.log("响应体: " + capturedResponses[i].body);
        }
        if (capturedResponses[i].bodyHex) {
            console.log("响应体(十六进制): " + capturedResponses[i].bodyHex);
        }
        console.log("-----------------------------------");
    }
};

global.clearCapturedData = function() {
    capturedRequests = [];
    capturedResponses = [];
    console.log("[*] 已清除所有捕获的数据");
};

console.log("[*] iOS网络监控已安装");
console.log("[*] 使用 showCapturedRequests() 查看捕获的请求");
console.log("[*] 使用 showCapturedResponses() 查看捕获的响应");
console.log("[*] 使用 clearCapturedData() 清除捕获的数据"); 