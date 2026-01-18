// complete_ios_rsa_monitor.js
console.log("[*] 开始全面监控iOS RSA加密/解密...");

// 监控CommonCrypto中的RSA函数
try {
    // 监控SecKeyEncrypt函数
    Interceptor.attach(Module.findExportByName(null, "SecKeyEncrypt"), {
        onEnter: function(args) {
            console.log("[+] SecKeyEncrypt 被调用");
            this.key = args[0];
            this.padding = args[1].toInt32();
            this.algorithm = args[2].toInt32();
            this.digest = args[3];
            this.digestLen = args[4].toInt32();
            this.encrypted = args[5];
            this.encryptedLen = args[6];
            
            console.log("    密钥: " + this.key);
            console.log("    填充方式: " + this.padding);
            console.log("    算法: " + this.algorithm);
            
            if (this.digest) {
                console.log("    输入数据: " + hexdump(this.digest, { length: this.digestLen }));
            }
        },
        onLeave: function(retval) {
            var result = retval.toInt32();
            console.log("    返回值: " + result);
            
            if (result === 0 && this.encrypted && this.encryptedLen) {
                var encryptedLen = Memory.readUInt(this.encryptedLen);
                console.log("    加密数据长度: " + encryptedLen);
                console.log("    加密数据: " + hexdump(this.encrypted, { length: encryptedLen }));
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook SecKeyEncrypt: " + e);
}

try {
    // 监控SecKeyDecrypt函数
    Interceptor.attach(Module.findExportByName(null, "SecKeyDecrypt"), {
        onEnter: function(args) {
            console.log("[+] SecKeyDecrypt 被调用");
            this.key = args[0];
            this.padding = args[1].toInt32();
            this.algorithm = args[2].toInt32();
            this.encrypted = args[3];
            this.encryptedLen = args[4].toInt32();
            this.decrypted = args[5];
            this.decryptedLen = args[6];
            
            console.log("    密钥: " + this.key);
            console.log("    填充方式: " + this.padding);
            console.log("    算法: " + this.algorithm);
            
            if (this.encrypted) {
                console.log("    输入数据: " + hexdump(this.encrypted, { length: this.encryptedLen }));
            }
        },
        onLeave: function(retval) {
            var result = retval.toInt32();
            console.log("    返回值: " + result);
            
            if (result === 0 && this.decrypted && this.decryptedLen) {
                var decryptedLen = Memory.readUInt(this.decryptedLen);
                console.log("    解密数据长度: " + decryptedLen);
                console.log("    解密数据: " + hexdump(this.decrypted, { length: decryptedLen }));
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook SecKeyDecrypt: " + e);
}

// 监控OpenSSL中的RSA函数
try {
    // 监控RSA_public_encrypt函数
    Interceptor.attach(Module.findExportByName(null, "RSA_public_encrypt"), {
        onEnter: function(args) {
            console.log("[+] RSA_public_encrypt 被调用");
            this.flen = args[1].toInt32();
            this.from = args[2];
            this.to = args[3];
            this.rsa = args[0];
            console.log("    输入长度: " + this.flen);
            console.log("    输入数据: " + hexdump(this.from, { length: this.flen }));
        },
        onLeave: function(retval) {
            var result = retval.toInt32();
            console.log("    返回值: " + result);
            if (result > 0) {
                console.log("    输出数据: " + hexdump(this.to, { length: result }));
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook RSA_public_encrypt: " + e);
}

try {
    // 监控RSA_private_decrypt函数
    Interceptor.attach(Module.findExportByName(null, "RSA_private_decrypt"), {
        onEnter: function(args) {
            console.log("[+] RSA_private_decrypt 被调用");
            this.flen = args[1].toInt32();
            this.from = args[2];
            this.to = args[3];
            this.rsa = args[0];
            console.log("    输入长度: " + this.flen);
            console.log("    输入数据: " + hexdump(this.from, { length: this.flen }));
        },
        onLeave: function(retval) {
            var result = retval.toInt32();
            console.log("    返回值: " + result);
            if (result > 0) {
                console.log("    输出数据: " + hexdump(this.to, { length: result }));
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook RSA_private_decrypt: " + e);
}

// 监控网络请求
Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter: function(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
        console.log("[+] send 被调用");
        console.log("    长度: " + this.len);
        console.log("    数据: " + hexdump(this.buf, { length: this.len }));
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
        }
    }
});

// 监控NSString和NSData相关函数
try {
    // 监控NSString initWithData
    Interceptor.attach(ObjC.classes.NSString["- initWithData:encoding:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSString initWithData:encoding: 被调用");
            this.data = args[1];
            this.encoding = args[2].toInt32();
            
            var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(this.data);
            console.log("    数据长度: " + dataLength);
            console.log("    编码: " + this.encoding);
            
            // 尝试读取数据
            var bytes = Memory.readByteArray(this.data, dataLength);
            console.log("    数据: " + hexdump(bytes, { length: dataLength }));
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSString initWithData:encoding:: " + e);
}

try {
    // 监控NSData dataWithBytes
    Interceptor.attach(ObjC.classes.NSData["+ dataWithBytes:length:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSData dataWithBytes:length: 被调用");
            this.bytes = args[1];
            this.length = args[2].toInt32();
            
            console.log("    长度: " + this.length);
            console.log("    数据: " + hexdump(this.bytes, { length: this.length }));
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSData dataWithBytes:length:: " + e);
}

// 监控Base64编码/解码
try {
    // 监控NSData base64EncodedStringWithOptions
    Interceptor.attach(ObjC.classes.NSData["- base64EncodedStringWithOptions:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSData base64EncodedStringWithOptions: 被调用");
            this.data = args[0];
            this.options = args[1].toInt32();
            
            var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(this.data);
            console.log("    数据长度: " + dataLength);
            console.log("    选项: " + this.options);
            
            // 尝试读取数据
            var bytes = Memory.readByteArray(this.data, dataLength);
            console.log("    数据: " + hexdump(bytes, { length: dataLength }));
        },
        onLeave: function(retval) {
            console.log("    返回的Base64字符串: " + ObjC.Object(retval).toString());
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSData base64EncodedStringWithOptions:: " + e);
}

try {
    // 监控NSData initWithBase64EncodedString
    Interceptor.attach(ObjC.classes.NSData["- initWithBase64EncodedString:options:"].implementation, {
        onEnter: function(args) {
            console.log("[+] NSData initWithBase64EncodedString:options: 被调用");
            this.base64String = args[1];
            this.options = args[2].toInt32();
            
            console.log("    Base64字符串: " + ObjC.Object(this.base64String).toString());
            console.log("    选项: " + this.options);
        },
        onLeave: function(retval) {
            var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(retval);
            console.log("    解码后数据长度: " + dataLength);
            
            // 尝试读取数据
            var bytes = Memory.readByteArray(retval, dataLength);
            console.log("    解码后数据: " + hexdump(bytes, { length: dataLength }));
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSData initWithBase64EncodedString:options:: " + e);
}

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
                } catch(e) {
                    console.log("    请求体不是有效的UTF-8字符串");
                }
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook NSURLSession dataTaskWithRequest:completionHandler:: " + e);
}

console.log("[*] iOS RSA监控已安装");