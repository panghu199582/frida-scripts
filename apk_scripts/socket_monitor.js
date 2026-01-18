/**
 * Socket通信监控Hook脚本
 * 专门监控Socket层面的请求和响应数据
 * 适用于基于Socket的HTTP/HTTPS通信
 */

Java.perform(function() {
    console.log("[+] Socket通信监控Hook脚本已启动");
    
    // 配置
    var config = {
        enableLogging: true,
        logSocketData: true,     // 记录Socket数据
        logSSLData: true,        // 记录SSL数据
        maxDataSize: 1024 * 1024, // 1MB
        saveToFile: false        // 暂时禁用文件写入
    };
    
    // 日志记录器
    var logger = {
        log: function(message) {
            if (!config.enableLogging) return;
            var timestamp = new Date().toLocaleString();
            var logMessage = "[" + timestamp + "] " + message;
            console.log(logMessage);
        },
        
        logSocketData: function(direction, data, length) {
            this.log("=== Socket " + direction + " ===");
            this.log("数据长度: " + length);
            this.log("数据内容: " + this.truncate(data, config.maxDataSize));
            this.log("================");
        },
        
        truncate: function(str, maxLength) {
            if (str && str.length > maxLength) {
                return str.substring(0, maxLength) + "...[截断]";
            }
            return str;
        },
        
        // 字节数组转字符串
        bytes2string: function(array) {
            try {
                return String.fromCharCode.apply(null, new Uint8Array(array));
            } catch(e) {
                return "[无法转换的二进制数据]";
            }
        },
        
        // 字节数组转十六进制
        bytes2hex: function(array) {
            var result = '';
            for (var i = 0; i < array.length; i++) {
                result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
            }
            return result;
        }
    };
    
    // 1. Hook Java Socket类
    function hookJavaSocket() {
        try {
            logger.log("[*] 设置Java Socket Hook...");
            
            var Socket = Java.use('java.net.Socket');
            if (Socket) {
                // Hook connect方法
                Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
                    logger.log("[+] Java Socket连接: " + endpoint.toString());
                    return this.connect(endpoint);
                };
                
                Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
                    logger.log("[+] Java Socket连接(带超时): " + endpoint.toString() + ", 超时: " + timeout);
                    return this.connect(endpoint, timeout);
                };
                
                // Hook getInputStream
                Socket.getInputStream.implementation = function() {
                    logger.log("[+] Java Socket获取输入流");
                    return this.getInputStream();
                };
                
                // Hook getOutputStream
                Socket.getOutputStream.implementation = function() {
                    logger.log("[+] Java Socket获取输出流");
                    return this.getOutputStream();
                };
                
                logger.log("[+] Java Socket Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] Java Socket Hook失败: " + e);
        }
    }
    
    // 2. Hook Socket InputStream
    function hookSocketInputStream() {
        try {
            logger.log("[*] 设置Socket InputStream Hook...");
            
            var SocketInputStream = Java.use('java.net.SocketInputStream');
            if (SocketInputStream) {
                // Hook read方法
                SocketInputStream.read.overload('[B').implementation = function(buffer) {
                    var result = this.read(buffer);
                    if (result > 0) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var sslInfo = parseSSLData(data);
                        
                        console.log("[+] Socket读取: " + result + " bytes");
                        if (sslInfo !== "数据太短") {
                            console.log("    SSL信息: " + sslInfo);
                        }
                        console.log("    数据: " + stringData);
                        console.log("    十六进制: " + hexData);
                    }
                    return result;
                };
                
                SocketInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                    var result = this.read(buffer, offset, length);
                    if (result > 0) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var sslInfo = parseSSLData(data);
                        
                        console.log("[+] Socket读取(offset=" + offset + ", length=" + length + "): " + result + " bytes");
                        if (sslInfo !== "数据太短") {
                            console.log("    SSL信息: " + sslInfo);
                        }
                        console.log("    数据: " + stringData);
                        console.log("    十六进制: " + hexData);
                    }
                    return result;
                };
                
                logger.log("[+] Socket InputStream Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] Socket InputStream Hook失败: " + e);
        }
    }
    
    // 3. Hook Socket OutputStream
    function hookSocketOutputStream() {
        try {
            logger.log("[*] 设置Socket OutputStream Hook...");
            
            var SocketOutputStream = Java.use('java.net.SocketOutputStream');
            if (SocketOutputStream) {
                // Hook write方法
                SocketOutputStream.write.overload('[B').implementation = function(buffer) {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var stringData = bytesToString(data);
                    var sslInfo = parseSSLData(data);
                    
                    console.log("[+] Socket写入: " + data.length + " bytes");
                    if (sslInfo !== "数据太短") {
                        console.log("    SSL信息: " + sslInfo);
                    }
                    console.log("    数据: " + stringData);
                    console.log("    十六进制: " + hexData);
                    return this.write(buffer);
                };
                
                SocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var stringData = bytesToString(data);
                    var sslInfo = parseSSLData(data);
                    
                    console.log("[+] Socket写入(offset=" + offset + ", length=" + length + "): " + length + " bytes");
                    if (sslInfo !== "数据太短") {
                        console.log("    SSL信息: " + sslInfo);
                    }
                    console.log("    数据: " + stringData);
                    console.log("    十六进制: " + hexData);
                    return this.write(buffer, offset, length);
                };
                
                logger.log("[+] Socket OutputStream Hook设置成功");
            }
        } catch(e) {
            logger.log("[-] Socket OutputStream Hook失败: " + e);
        }
    }
    
    // 4. Hook BufferedInputStream
    function hookBufferedInputStream() {
        try {
            logger.log("[*] 设置BufferedInputStream Hook...");
            
            var BufferedInputStream = Java.use("java.io.BufferedInputStream");
            
            // Hook read() methods with correct signatures
            BufferedInputStream.read.overload().implementation = function() {
                var result = this.read();
                if (result !== -1) {
                    var data = String.fromCharCode(result);
                    console.log("[+] BufferedInputStream.read(): " + result + " ('" + data + "')");
                }
                return result;
            };
            
            BufferedInputStream.read.overload('[B').implementation = function(buffer) {
                var result = this.read(buffer);
                if (result > 0) {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var strData = bytesToString(data);
                    var sslInfo = parseSSLData(data);
                    
                    console.log("[+] BufferedInputStream.read(buffer): " + result + " bytes");
                    if (sslInfo !== "数据太短") {
                        console.log("    SSL信息: " + sslInfo);
                    }
                    console.log("    数据: " + strData);
                    console.log("    十六进制: " + hexData);
                }
                return result;
            };
            
            BufferedInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                var result = this.read(buffer, offset, length);
                if (result > 0) {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var strData = bytesToString(data);
                    var sslInfo = parseSSLData(data);
                    
                    console.log("[+] BufferedInputStream.read(buffer, " + offset + ", " + length + "): " + result + " bytes");
                    if (sslInfo !== "数据太短") {
                        console.log("    SSL信息: " + sslInfo);
                    }
                    console.log("    数据: " + strData);
                    console.log("    十六进制: " + hexData);
                }
                return result;
            };
            
            logger.log("[+] BufferedInputStream Hook设置成功");
        } catch(e) {
            logger.log("[-] BufferedInputStream Hook失败: " + e);
        }
    }
    
    // 5. Hook BufferedOutputStream
    function hookBufferedOutputStream() {
        try {
            logger.log("[*] 设置BufferedOutputStream Hook...");
            
            var BufferedOutputStream = Java.use("java.io.BufferedOutputStream");
            
            // Hook write() methods with correct signatures
            BufferedOutputStream.write.overload('int').implementation = function(b) {
                this.write(b);
                var data = String.fromCharCode(b);
                console.log("[+] BufferedOutputStream.write(int): " + b + " ('" + data + "')");
            };
            
            BufferedOutputStream.write.overload('[B').implementation = function(buffer) {
                this.write(buffer);
                var data = Java.array('byte', buffer);
                var hexData = bytesToHex(data);
                var strData = bytesToString(data);
                var sslInfo = parseSSLData(data);
                
                console.log("[+] BufferedOutputStream.write(buffer): " + buffer.length + " bytes");
                if (sslInfo !== "数据太短") {
                    console.log("    SSL信息: " + sslInfo);
                }
                console.log("    数据: " + strData);
                console.log("    十六进制: " + hexData);
            };
            
            BufferedOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                this.write(buffer, offset, length);
                var data = Java.array('byte', buffer);
                var hexData = bytesToHex(data);
                var strData = bytesToString(data);
                var sslInfo = parseSSLData(data);
                
                console.log("[+] BufferedOutputStream.write(buffer, " + offset + ", " + length + "): " + length + " bytes");
                if (sslInfo !== "数据太短") {
                    console.log("    SSL信息: " + sslInfo);
                }
                console.log("    数据: " + strData);
                console.log("    十六进制: " + hexData);
            };
            
            logger.log("[+] BufferedOutputStream Hook设置成功");
        } catch(e) {
            logger.log("[-] BufferedOutputStream Hook失败: " + e);
        }
    }
    
    // 6. Hook SSL/TLS底层函数
    function hookSSLFunctions() {
        try {
            logger.log("[*] 设置SSL/TLS底层函数Hook...");
            
            // Hook SSL_write
            var sslWritePtr = Module.findExportByName(null, 'SSL_write');
            if (sslWritePtr) {
                Interceptor.attach(sslWritePtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 10000) { // 增加大小限制
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = bytesToHex(data);
                                var stringData = bytesToString(data);
                                var sslInfo = parseSSLData(data);
                                
                                console.log("[+] SSL写入: " + len + " bytes");
                                console.log("    SSL信息: " + sslInfo);
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        } catch(e) {
                            console.log("[-] SSL_write Hook错误: " + e);
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
                            if (len > 0 && len < 10000) { // 增加大小限制
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = bytesToHex(data);
                                var stringData = bytesToString(data);
                                var sslInfo = parseSSLData(data);
                                
                                console.log("[+] SSL读取: " + len + " bytes");
                                console.log("    SSL信息: " + sslInfo);
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        } catch(e) {
                            console.log("[-] SSL_read Hook错误: " + e);
                        }
                    }
                });
            }
            
            logger.log("[+] SSL/TLS底层函数Hook设置成功");
        } catch(e) {
            logger.log("[-] SSL/TLS底层函数Hook失败: " + e);
        }
    }
    
    // 7. Hook 系统调用级别的Socket函数
    function hookSystemSocketCalls() {
        try {
            logger.log("[*] 设置系统调用级别Socket函数Hook...");
            
            // Hook send系统调用
            var sendPtr = Module.findExportByName(null, 'send');
            if (sendPtr) {
                Interceptor.attach(sendPtr, {
                    onEnter: function(args) {
                        try {
                            var len = args[2].toInt32();
                            if (len > 0 && len < 10000) {
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = bytesToHex(data);
                                var stringData = bytesToString(data);
                                
                                console.log("[+] 系统send: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        } catch(e) {
                            console.log("[-] send系统调用Hook错误: " + e);
                        }
                    }
                });
            }
            
            // Hook recv系统调用
            var recvPtr = Module.findExportByName(null, 'recv');
            if (recvPtr) {
                Interceptor.attach(recvPtr, {
                    onLeave: function(retval) {
                        try {
                            var len = retval.toInt32();
                            if (len > 0 && len < 10000) {
                                var data = Memory.readByteArray(args[1], len);
                                var hexData = bytesToHex(data);
                                var stringData = bytesToString(data);
                                
                                console.log("[+] 系统recv: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        } catch(e) {
                            console.log("[-] recv系统调用Hook错误: " + e);
                        }
                    }
                });
            }
            
            logger.log("[+] 系统调用级别Socket函数Hook设置成功");
        } catch(e) {
            logger.log("[-] 系统调用级别Socket函数Hook失败: " + e);
        }
    }
    
    // 8. Hook 应用特定的Socket类
    function hookAppSpecificSocketClasses() {
        try {
            logger.log("[*] 尝试Hook应用特定的Socket类...");
            
            // 尝试Hook一些可能的Socket相关类
            var classesToTry = [
                "com.acb.mobile.network.SocketManager",
                "com.acb.mobile.network.SocketClient",
                "com.acb.mobile.network.NetworkSocket",
                "com.acb.mobile.network.SocketConnection",
                "com.acb.mobile.network.SocketHandler",
                "com.acb.mobile.network.SocketService",
                "com.acb.mobile.network.SocketRequest",
                "com.acb.mobile.network.SocketResponse"
            ];
            
            classesToTry.forEach(function(className) {
                try {
                    var cls = Java.use(className);
                    if (cls) {
                        logger.log("[+] 找到应用特定Socket类: " + className);
                        
                        // 尝试Hook所有方法
                        var methods = cls.class.getDeclaredMethods();
                        methods.forEach(function(method) {
                            try {
                                var methodName = method.getName();
                                if (methodName.indexOf("send") !== -1 || 
                                    methodName.indexOf("receive") !== -1 ||
                                    methodName.indexOf("write") !== -1 ||
                                    methodName.indexOf("read") !== -1 ||
                                    methodName.indexOf("connect") !== -1 ||
                                    methodName.indexOf("request") !== -1 ||
                                    methodName.indexOf("response") !== -1) {
                                    
                                    logger.log("[*] Hook Socket方法: " + className + "." + methodName);
                                    cls[methodName].implementation = function() {
                                        logger.log("[+] 调用Socket方法: " + className + "." + methodName);
                                        logger.log("[*] 参数: " + JSON.stringify(arguments));
                                        return this[methodName].apply(this, arguments);
                                    };
                                }
                            } catch(e) {
                                // 忽略单个方法Hook失败
                            }
                        });
                    }
                } catch(e) {
                    // 类不存在，忽略
                }
            });
            
        } catch(e) {
            logger.log("[-] 应用特定Socket类Hook失败: " + e);
        }
    }
    
    // 主函数
    function main() {
        logger.log("[*] Socket通信监控Hook脚本初始化...");
        
        // 延迟执行，确保所有类都已加载
        setTimeout(function() {
            // 设置所有Socket Hook
            hookJavaSocket();
            hookSocketInputStream();
            hookSocketOutputStream();
            hookBufferedInputStream();
            hookBufferedOutputStream();
            hookSSLFunctions();
            hookSystemSocketCalls();
            hookAppSpecificSocketClasses();
            
            logger.log("[+] 所有Socket Hook已设置完成");
            logger.log("[*] 开始监控Socket通信...");
            logger.log("[*] 监控内容:");
            logger.log("  - Java Socket连接");
            logger.log("  - Socket输入输出流");
            logger.log("  - 缓冲输入输出流");
            logger.log("  - SSL/TLS底层通信");
            logger.log("  - 系统调用级别Socket");
            logger.log("  - 应用特定Socket类");
            logger.log("[*] 所有Socket数据都会以字符串和十六进制格式显示");
        }, 2000);
    }
    
    // 启动主函数
    main();
});

// 使用说明：
// 1. 将此脚本保存为 socket_monitor.js
// 2. 使用Frida注入: frida -U -f com.target.app -l socket_monitor.js
// 3. 脚本会监控所有Socket层面的通信数据
// 4. 所有Socket数据都会在控制台输出 

// 改进的数据转换函数
function bytesToHex(bytes) {
    if (!bytes || bytes.length === 0) return "";
    var hex = "";
    for (var i = 0; i < Math.min(bytes.length, 100); i++) { // 限制显示长度
        var b = bytes[i] & 0xff;
        hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    if (bytes.length > 100) hex += "...";
    return hex;
}

function bytesToString(bytes) {
    if (!bytes || bytes.length === 0) return "";
    var str = "";
    for (var i = 0; i < Math.min(bytes.length, 100); i++) { // 限制显示长度
        var b = bytes[i] & 0xff;
        // 只显示可打印字符，其他用点号表示
        if (b >= 32 && b <= 126) {
            str += String.fromCharCode(b);
        } else {
            str += ".";
        }
    }
    if (bytes.length > 100) str += "...";
    return str;
}

// 改进的SSL数据解析函数
function parseSSLData(data) {
    if (!data || data.length < 5) return "数据太短";
    
    var contentType = data[0] & 0xff;
    var version = ((data[1] & 0xff) << 8) | (data[2] & 0xff);
    var length = ((data[3] & 0xff) << 8) | (data[4] & 0xff);
    
    var contentTypeStr = "";
    switch (contentType) {
        case 0x14: contentTypeStr = "Change Cipher Spec"; break;
        case 0x15: contentTypeStr = "Alert"; break;
        case 0x16: contentTypeStr = "Handshake"; break;
        case 0x17: contentTypeStr = "Application Data"; break;
        default: contentTypeStr = "Unknown(" + contentType + ")";
    }
    
    var versionStr = "";
    switch (version) {
        case 0x0300: versionStr = "SSL 3.0"; break;
        case 0x0301: versionStr = "TLS 1.0"; break;
        case 0x0302: versionStr = "TLS 1.1"; break;
        case 0x0303: versionStr = "TLS 1.2"; break;
        case 0x0304: versionStr = "TLS 1.3"; break;
        default: versionStr = "Unknown(" + version + ")";
    }
    
    return contentTypeStr + " | " + versionStr + " | 长度: " + length;
} 