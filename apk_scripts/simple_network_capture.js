/*
 * 简单网络抓包脚本
 * 基于APK分析结果生成
 */

console.log("[+] 简单网络抓包脚本已启动");

Java.perform(function() {
    console.log("[+] Java.perform执行成功");
    
    // 1. Hook HttpURLConnection (最稳定)
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.getOutputStream.implementation = function() {
            try {
                var url = this.getURL().toString();
                var method = this.getRequestMethod();
                console.log("[+] HttpURLConnection: " + method + " " + url);
            } catch (e) {
                console.log("[-] HttpURLConnection Hook错误: " + e);
            }
            return this.getOutputStream();
        };
        
        console.log("[+] HttpURLConnection Hook设置成功");
    } catch (e) {
        console.log("[-] HttpURLConnection Hook失败: " + e);
    }
    
    // 2. Hook Socket连接
    try {
        var Socket = Java.use("java.net.Socket");
        
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            console.log("[+] Socket连接: " + host + ":" + port);
            return result;
        };
        
        console.log("[+] Socket Hook设置成功");
    } catch(e) {
        console.log("[-] Socket Hook失败: " + e);
    }
    
    // 3. 尝试Hook找到的类（限制数量）
    console.log("[*] 开始Hook找到的类...");
    

    // Hook okhttp 相关类
    try {
        var okhttp3_Cache = Java.use("okhttp3.Cache");
        console.log("[+] 成功加载类: okhttp3.Cache");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okhttp3_Call = Java.use("okhttp3.Call");
        console.log("[+] 成功加载类: okhttp3.Call");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okhttp3_Dns = Java.use("okhttp3.Dns");
        console.log("[+] 成功加载类: okhttp3.Dns");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okhttp3_HttpUrl_Companion = Java.use("okhttp3.HttpUrl$Companion");
        console.log("[+] 成功加载类: okhttp3.HttpUrl$Companion");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okhttp3_HttpUrl = Java.use("okhttp3.HttpUrl");
        console.log("[+] 成功加载类: okhttp3.HttpUrl");
    } catch (e) {
        // 类不存在或无法加载
    }

    // Hook retrofit 相关类
    try {
        var retrofit2_Call = Java.use("retrofit2.Call");
        console.log("[+] 成功加载类: retrofit2.Call");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var retrofit2_Callback = Java.use("retrofit2.Callback");
        console.log("[+] 成功加载类: retrofit2.Callback");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var retrofit2_Converter_Factory = Java.use("retrofit2.Converter$Factory");
        console.log("[+] 成功加载类: retrofit2.Converter$Factory");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var retrofit2_HttpException = Java.use("retrofit2.HttpException");
        console.log("[+] 成功加载类: retrofit2.HttpException");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var retrofit2_Response = Java.use("retrofit2.Response");
        console.log("[+] 成功加载类: retrofit2.Response");
    } catch (e) {
        // 类不存在或无法加载
    }

    // Hook okio 相关类
    try {
        var okio_ByteString = Java.use("okio.ByteString");
        console.log("[+] 成功加载类: okio.ByteString");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okio_ByteString = Java.use("okio.ByteString");
        console.log("[+] 成功加载类: okio.ByteString");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okio_Buffer = Java.use("okio.Buffer");
        console.log("[+] 成功加载类: okio.Buffer");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okio_BufferedSink = Java.use("okio.BufferedSink");
        console.log("[+] 成功加载类: okio.BufferedSink");
    } catch (e) {
        // 类不存在或无法加载
    }
    try {
        var okio_Buffer = Java.use("okio.Buffer");
        console.log("[+] 成功加载类: okio.Buffer");
    } catch (e) {
        // 类不存在或无法加载
    }

    // Hook 网络相关方法（简化版）
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.newCall && typeof clazz.newCall === 'function') {
                    console.log("[!] 发现 newCall 方法: " + className);
                    
                    // 简单Hook
                    clazz.newCall.implementation = function() {
                        console.log("[+] 调用 newCall 方法: " + className);
                        return this.newCall.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.execute && typeof clazz.execute === 'function') {
                    console.log("[!] 发现 execute 方法: " + className);
                    
                    // 简单Hook
                    clazz.execute.implementation = function() {
                        console.log("[+] 调用 execute 方法: " + className);
                        return this.execute.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.getInputStream && typeof clazz.getInputStream === 'function') {
                    console.log("[!] 发现 getInputStream 方法: " + className);
                    
                    // 简单Hook
                    clazz.getInputStream.implementation = function() {
                        console.log("[+] 调用 getInputStream 方法: " + className);
                        return this.getInputStream.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.connect && typeof clazz.connect === 'function') {
                    console.log("[!] 发现 connect 方法: " + className);
                    
                    // 简单Hook
                    clazz.connect.implementation = function() {
                        console.log("[+] 调用 connect 方法: " + className);
                        return this.connect.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.write && typeof clazz.write === 'function') {
                    console.log("[!] 发现 write 方法: " + className);
                    
                    // 简单Hook
                    clazz.write.implementation = function() {
                        console.log("[+] 调用 write 方法: " + className);
                        return this.write.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.read && typeof clazz.read === 'function') {
                    console.log("[!] 发现 read 方法: " + className);
                    
                    // 简单Hook
                    clazz.read.implementation = function() {
                        console.log("[+] 调用 read 方法: " + className);
                        return this.read.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.url && typeof clazz.url === 'function') {
                    console.log("[!] 发现 url 方法: " + className);
                    
                    // 简单Hook
                    clazz.url.implementation = function() {
                        console.log("[+] 调用 url 方法: " + className);
                        return this.url.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.method && typeof clazz.method === 'function') {
                    console.log("[!] 发现 method 方法: " + className);
                    
                    // 简单Hook
                    clazz.method.implementation = function() {
                        console.log("[+] 调用 method 方法: " + className);
                        return this.method.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.body && typeof clazz.body === 'function') {
                    console.log("[!] 发现 body 方法: " + className);
                    
                    // 简单Hook
                    clazz.body.implementation = function() {
                        console.log("[+] 调用 body 方法: " + className);
                        return this.body.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                if (clazz.string && typeof clazz.string === 'function') {
                    console.log("[!] 发现 string 方法: " + className);
                    
                    // 简单Hook
                    clazz.string.implementation = function() {
                        console.log("[+] 调用 string 方法: " + className);
                        return this.string.apply(this, arguments);
                    };
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });

    console.log("[+] 脚本设置完成");
    console.log("[*] 开始监控网络请求...");
});
