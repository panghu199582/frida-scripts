console.log("[*] 开始搜索iOS应用中的硬编码密钥...");

// 搜索常见的密钥格式
function searchForKeys() {
    // 搜索Base64编码的密钥
    var base64Pattern = /[A-Za-z0-9+/]{100,}={0,2}/g;
    
    // 搜索十六进制编码的密钥
    var hexPattern = /[0-9A-Fa-f]{64,}/g;
    
    // 搜索PEM格式的密钥
    var pemPattern = /-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END (RSA )?(PUBLIC|PRIVATE) KEY-----/g;
    
    // 搜索常见的密钥变量名
    var keyVarNames = [
        "key", "secret", "privateKey", "publicKey", "rsaKey", "encryptionKey", 
        "decryptionKey", "apiKey", "token", "password", "certificate", "pem"
    ];
    
    // 搜索所有加载的模块
    var modules = Process.enumerateModules();
    console.log("[+] 已加载模块数量: " + modules.length);
    
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        console.log("[*] 搜索模块: " + module.name);
        
        // 搜索模块中的字符串
        var strings = module.enumerateStrings();
        console.log("    - 字符串数量: " + strings.length);
        
        for (var j = 0; j < strings.length; j++) {
            var str = strings[j];
            
            // 检查是否匹配Base64模式
            if (base64Pattern.test(str)) {
                console.log("[!] 发现可能的Base64密钥: " + str);
            }
            
            // 检查是否匹配十六进制模式
            if (hexPattern.test(str)) {
                console.log("[!] 发现可能的十六进制密钥: " + str);
            }
            
            // 检查是否匹配PEM模式
            if (pemPattern.test(str)) {
                console.log("[!] 发现可能的PEM密钥: " + str);
            }
            
            // 检查是否包含密钥变量名
            for (var k = 0; k < keyVarNames.length; k++) {
                if (str.toLowerCase().includes(keyVarNames[k].toLowerCase())) {
                    console.log("[!] 发现可能的密钥相关字符串: " + str);
                    break;
                }
            }
        }
    }
    
    // 搜索ObjC类中的字符串
    var classes = ObjC.classes;
    for (var className in classes) {
        var methods = classes[className].$methods;
        for (var i = 0; i < methods.length; i++) {
            var methodName = methods[i];
            try {
                var implementation = classes[className][methodName].implementation;
                var methodStr = implementation.toString();
                
                // 检查是否匹配Base64模式
                if (base64Pattern.test(methodStr)) {
                    console.log("[!] 在方法中发现可能的Base64密钥: " + className + " " + methodName);
                }
                
                // 检查是否匹配十六进制模式
                if (hexPattern.test(methodStr)) {
                    console.log("[!] 在方法中发现可能的十六进制密钥: " + className + " " + methodName);
                }
                
                // 检查是否匹配PEM模式
                if (pemPattern.test(methodStr)) {
                    console.log("[!] 在方法中发现可能的PEM密钥: " + className + " " + methodName);
                }
            } catch(e) {
                // 忽略无法访问的实现
            }
        }
    }
}

// 执行搜索
searchForKeys();

// 监控密钥加载函数
try {
    // 监控SecItemAdd
    Interceptor.attach(Module.findExportByName(null, "SecItemAdd"), {
        onEnter: function(args) {
            console.log("[+] SecItemAdd 被调用");
            this.attributes = args[0];
            this.result = args[1];
            
            // 尝试读取属性
            var classType = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.attributes, "class");
            var keyType = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.attributes, "kattrKeyType");
            var keyClass = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.attributes, "kattrKeyClass");
            
            console.log("    类: " + ObjC.Object(classType).toString());
            console.log("    密钥类型: " + ObjC.Object(keyType).toString());
            console.log("    密钥类: " + ObjC.Object(keyClass).toString());
            
            // 如果是RSA密钥，尝试提取
            if (ObjC.Object(keyType).toString() === "RSA") {
                var valueData = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.attributes, "v_Data");
                if (valueData) {
                    var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(valueData);
                    console.log("    密钥数据长度: " + dataLength);
                    
                    // 尝试读取密钥数据
                    var bytes = Memory.readByteArray(valueData, dataLength);
                    console.log("    密钥数据: " + hexdump(bytes, { length: dataLength }));
                    
                    // 尝试解析为Base64
                    try {
                        var base64 = ObjC.classes.NSData.instanceMethod_base64EncodedStringWithOptions_(valueData, 0).toString();
                        console.log("    密钥数据(Base64): " + base64);
                    } catch(e) {
                        console.log("    无法将密钥数据转换为Base64");
                    }
                }
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook SecItemAdd: " + e);
}

// 监控SecItemCopyMatching
try {
    Interceptor.attach(Module.findExportByName(null, "SecItemCopyMatching"), {
        onEnter: function(args) {
            console.log("[+] SecItemCopyMatching 被调用");
            this.query = args[0];
            this.result = args[1];
            
            // 尝试读取查询
            var classType = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.query, "class");
            var keyType = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.query, "kattrKeyType");
            var keyClass = ObjC.classes.NSDictionary.instanceMethod_objectForKey_(this.query, "kattrKeyClass");
            
            console.log("    类: " + ObjC.Object(classType).toString());
            console.log("    密钥类型: " + ObjC.Object(keyType).toString());
            console.log("    密钥类: " + ObjC.Object(keyClass).toString());
        },
        onLeave: function(retval) {
            if (retval) {
                var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(retval);
                console.log("    返回数据长度: " + dataLength);
                
                // 尝试读取返回数据
                var bytes = Memory.readByteArray(retval, dataLength);
                console.log("    返回数据: " + hexdump(bytes, { length: dataLength }));
                
                // 尝试解析为Base64
                try {
                    var base64 = ObjC.classes.NSData.instanceMethod_base64EncodedStringWithOptions_(retval, 0).toString();
                    console.log("    返回数据(Base64): " + base64);
                } catch(e) {
                    console.log("    无法将返回数据转换为Base64");
                }
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook SecItemCopyMatching: " + e);
}

// 监控SecKeyCreateWithData
try {
    Interceptor.attach(Module.findExportByName(null, "SecKeyCreateWithData"), {
        onEnter: function(args) {
            console.log("[+] SecKeyCreateWithData 被调用");
            this.allocator = args[0];
            this.attributes = args[1];
            this.data = args[2];
            this.error = args[3];
            
            var dataLength = ObjC.classes.NSData.instanceMethod_getLength_(this.data);
            console.log("    密钥数据长度: " + dataLength);
            
            // 尝试读取密钥数据
            var bytes = Memory.readByteArray(this.data, dataLength);
            console.log("    密钥数据: " + hexdump(bytes, { length: dataLength }));
            
            // 尝试解析为Base64
            try {
                var base64 = ObjC.classes.NSData.instanceMethod_base64EncodedStringWithOptions_(this.data, 0).toString();
                console.log("    密钥数据(Base64): " + base64);
            } catch(e) {
                console.log("    无法将密钥数据转换为Base64");
            }
        }
    });
} catch(e) {
    console.log("[-] 无法hook SecKeyCreateWithData: " + e);
}

// 监控SecKeyEncrypt和SecKeyDecrypt
try {
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

// 监控网络请求中的加密数据
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

console.log("[*] iOS密钥搜索脚本已安装"); 