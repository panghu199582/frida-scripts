/*
 * ACB深度Socket监控脚本
 * 专门监控apiapp.acb.com.vn:443接口的详细数据
 */

console.log("[+] ACB深度Socket监控脚本已启动");

// 目标接口
var TARGET_HOST = "apiapp.acb.com.vn";
var TARGET_PORT = 443;

// 记录目标连接
var targetConnections = {};

Java.perform(function() {
    console.log("[*] ACB深度Socket监控脚本初始化...");
    console.log("[*] 目标接口: " + TARGET_HOST + ":" + TARGET_PORT);
    
    // 1. Hook Java Socket连接
    try {
        console.log("[*] 设置Java Socket Hook...");
        
        var Socket = Java.use("java.net.Socket");
        
        // Hook Socket构造函数
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            if (host === TARGET_HOST && port === TARGET_PORT) {
                console.log("[+] 目标Socket连接: " + host + ":" + port);
                targetConnections[this.hashCode()] = {
                    host: host,
                    port: port,
                    type: "Java Socket"
                };
            }
            return result;
        };
        
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            var result = this.connect(endpoint, timeout);
            try {
                var host = this.getInetAddress().getHostName();
                var port = this.getPort();
                if (host === TARGET_HOST && port === TARGET_PORT) {
                    console.log("[+] 目标Socket连接(带超时): " + host + ":" + port + ", 超时: " + timeout);
                    targetConnections[this.hashCode()] = {
                        host: host,
                        port: port,
                        type: "Java Socket"
                    };
                }
            } catch(e) {
                // 忽略错误
            }
            return result;
        };
        
        console.log("[+] Java Socket Hook设置成功");
    } catch(e) {
        console.log("[-] Java Socket Hook失败: " + e);
    }
    
    // 2. Hook Socket输入输出流 (只监控目标连接)
    try {
        console.log("[*] 设置Socket流Hook...");
        
        var SocketInputStream = Java.use('java.net.SocketInputStream');
        if (SocketInputStream) {
            SocketInputStream.read.overload('[B').implementation = function(buffer) {
                var result = this.read(buffer);
                if (result > 0) {
                    try {
                        var socketHash = this.socket.hashCode();
                        if (targetConnections[socketHash]) {
                            var data = Java.array('byte', buffer);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            var connInfo = targetConnections[socketHash];
                            
                            console.log("[+] 目标Socket读取: " + connInfo.host + ":" + connInfo.port + " -> " + result + " bytes");
                            console.log("    数据: " + stringData);
                            console.log("    十六进制: " + hexData);
                            
                            // 尝试解析HTTP响应
                            if (stringData.indexOf("HTTP/") === 0) {
                                console.log("    [HTTP响应] " + stringData.split('\n')[0]);
                            }
                            
                            // 尝试解析JSON
                            if (stringData.indexOf("{") !== -1 && stringData.indexOf("}") !== -1) {
                                console.log("    [可能的JSON数据]");
                            }
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
                return result;
            };
            
            SocketInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                var result = this.read(buffer, offset, length);
                if (result > 0) {
                    try {
                        var socketHash = this.socket.hashCode();
                        if (targetConnections[socketHash]) {
                            var data = Java.array('byte', buffer);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            var connInfo = targetConnections[socketHash];
                            
                            console.log("[+] 目标Socket读取(offset=" + offset + ", length=" + length + "): " + connInfo.host + ":" + connInfo.port + " -> " + result + " bytes");
                            console.log("    数据: " + stringData);
                            console.log("    十六进制: " + hexData);
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
                return result;
            };
        }
        
        var SocketOutputStream = Java.use('java.net.SocketOutputStream');
        if (SocketOutputStream) {
            SocketOutputStream.write.overload('[B').implementation = function(buffer) {
                try {
                    var socketHash = this.socket.hashCode();
                    if (targetConnections[socketHash]) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var connInfo = targetConnections[socketHash];
                        
                        console.log("[+] 目标Socket写入: " + connInfo.host + ":" + connInfo.port + " -> " + data.length + " bytes");
                        console.log("    数据: " + stringData);
                        console.log("    十六进制: " + hexData);
                        
                        // 尝试解析HTTP请求
                        if (stringData.indexOf("GET ") === 0 || stringData.indexOf("POST ") === 0) {
                            console.log("    [HTTP请求] " + stringData.split('\n')[0]);
                        }
                        
                        // 尝试解析JSON
                        if (stringData.indexOf("{") !== -1 && stringData.indexOf("}") !== -1) {
                            console.log("    [可能的JSON数据]");
                        }
                    }
                } catch(e) {
                    // 忽略错误
                }
                return this.write(buffer);
            };
            
            SocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
                try {
                    var socketHash = this.socket.hashCode();
                    if (targetConnections[socketHash]) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var connInfo = targetConnections[socketHash];
                        
                        console.log("[+] 目标Socket写入(offset=" + offset + ", length=" + length + "): " + connInfo.host + ":" + connInfo.port + " -> " + length + " bytes");
                        console.log("    数据: " + stringData);
                        console.log("    十六进制: " + hexData);
                    }
                } catch(e) {
                    // 忽略错误
                }
                return this.write(buffer, offset, length);
            };
        }
        
        console.log("[+] Socket流Hook设置成功");
    } catch(e) {
        console.log("[-] Socket流Hook失败: " + e);
    }
    
    // 3. Hook 所有InputStream读取 (尝试捕获解密后的数据)
    try {
        console.log("[*] 设置全局InputStream Hook...");
        
        var InputStream = Java.use("java.io.InputStream");
        
        InputStream.read.overload('[B').implementation = function(buffer) {
            var result = this.read(buffer);
            if (result > 0) {
                try {
                    var data = Java.array('byte', buffer);
                    var hexData = bytesToHex(data);
                    var strData = bytesToString(data);
                    
                    // 检查是否包含目标域名或相关数据
                    if (strData.indexOf("apiapp.acb.com.vn") !== -1 || 
                        strData.indexOf("acb.com") !== -1 ||
                        strData.indexOf("ACB") !== -1 ||
                        strData.indexOf("HTTP/") === 0 ||
                        strData.indexOf("GET ") === 0 || 
                        strData.indexOf("POST ") === 0 ||
                        strData.indexOf("Content-Type:") !== -1 ||
                        strData.indexOf("login") !== -1 ||
                        strData.indexOf("auth") !== -1 ||
                        strData.indexOf("password") !== -1 ||
                        strData.indexOf("username") !== -1 ||
                        strData.indexOf("{") !== -1) {
                        
                        console.log("[+] 可能的ACB数据读取: " + result + " bytes");
                        console.log("    数据: " + strData);
                        console.log("    十六进制: " + hexData);
                    }
                } catch(e) {
                    // 忽略错误
                }
            }
            return result;
        };
        
        console.log("[+] 全局InputStream Hook设置成功");
    } catch(e) {
        console.log("[-] 全局InputStream Hook失败: " + e);
    }
    
    // 4. Hook 所有OutputStream写入
    try {
        console.log("[*] 设置全局OutputStream Hook...");
        
        var OutputStream = Java.use("java.io.OutputStream");
        
        OutputStream.write.overload('[B').implementation = function(buffer) {
            try {
                var data = Java.array('byte', buffer);
                var hexData = bytesToHex(data);
                var strData = bytesToString(data);
                
                // 检查是否包含目标域名或相关数据
                if (strData.indexOf("apiapp.acb.com.vn") !== -1 || 
                    strData.indexOf("acb.com") !== -1 ||
                    strData.indexOf("ACB") !== -1 ||
                    strData.indexOf("GET ") === 0 || 
                    strData.indexOf("POST ") === 0 ||
                    strData.indexOf("Host:") !== -1 ||
                    strData.indexOf("login") !== -1 ||
                    strData.indexOf("auth") !== -1 ||
                    strData.indexOf("password") !== -1 ||
                    strData.indexOf("username") !== -1 ||
                    strData.indexOf("{") !== -1) {
                    
                    console.log("[+] 可能的ACB数据写入: " + data.length + " bytes");
                    console.log("    数据: " + strData);
                    console.log("    十六进制: " + hexData);
                }
            } catch(e) {
                // 忽略错误
            }
            return this.write(buffer);
        };
        
        console.log("[+] 全局OutputStream Hook设置成功");
    } catch(e) {
        console.log("[-] 全局OutputStream Hook失败: " + e);
    }
    
    // 5. Hook SSL/TLS底层函数 (只监控目标相关)
    try {
        console.log("[*] 设置SSL/TLS底层函数Hook...");
        
        // Hook SSL_write
        var sslWritePtr = Module.findExportByName(null, 'SSL_write');
        if (sslWritePtr) {
            Interceptor.attach(sslWritePtr, {
                onEnter: function(args) {
                    try {
                        var len = args[2].toInt32();
                        if (len > 0 && len < 10000) {
                            var data = Memory.readByteArray(args[1], len);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            
                            // 检查是否包含目标域名或相关数据
                            if (stringData.indexOf("apiapp.acb.com.vn") !== -1 || 
                                stringData.indexOf("acb.com") !== -1 ||
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("Host:") !== -1 ||
                                stringData.indexOf("login") !== -1 ||
                                stringData.indexOf("auth") !== -1 ||
                                stringData.indexOf("password") !== -1 ||
                                stringData.indexOf("username") !== -1 ||
                                stringData.indexOf("GET ") === 0 ||
                                stringData.indexOf("POST ") === 0) {
                                
                                console.log("[+] ACB SSL写入: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        }
                    } catch(e) {
                        // 忽略错误
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
                        if (len > 0 && len < 10000) {
                            var data = Memory.readByteArray(args[1], len);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            
                            // 检查是否包含ACB相关数据
                            if (stringData.indexOf("apiapp.acb.com.vn") !== -1 || 
                                stringData.indexOf("acb.com") !== -1 ||
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("HTTP/") === 0 ||
                                stringData.indexOf("Content-Type:") !== -1 ||
                                stringData.indexOf("login") !== -1 ||
                                stringData.indexOf("auth") !== -1 ||
                                stringData.indexOf("{") !== -1) {
                                
                                console.log("[+] ACB SSL读取: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
            });
        }
        
        console.log("[+] SSL/TLS底层函数Hook设置成功");
    } catch(e) {
        console.log("[-] SSL/TLS底层函数Hook失败: " + e);
    }
    
    // 6. Hook 系统调用级别的Socket函数
    try {
        console.log("[*] 设置系统调用级别Socket函数Hook...");
        
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
                            
                            // 检查是否包含目标相关数据
                            if (stringData.indexOf("apiapp.acb.com.vn") !== -1 || 
                                stringData.indexOf("acb.com") !== -1 ||
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("GET ") === 0 ||
                                stringData.indexOf("POST ") === 0 ||
                                stringData.indexOf("Host:") !== -1) {
                                
                                console.log("[+] 系统send: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        }
                    } catch(e) {
                        // 忽略错误
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
                            
                            // 检查是否包含ACB相关数据
                            if (stringData.indexOf("apiapp.acb.com.vn") !== -1 || 
                                stringData.indexOf("acb.com") !== -1 ||
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("HTTP/") === 0 ||
                                stringData.indexOf("Content-Type:") !== -1 ||
                                stringData.indexOf("{") !== -1) {
                                
                                console.log("[+] 系统recv: " + len + " bytes");
                                console.log("    数据: " + stringData);
                                console.log("    十六进制: " + hexData);
                            }
                        }
                    } catch(e) {
                        // 忽略错误
                    }
                }
            });
        }
        
        console.log("[+] 系统调用级别Socket函数Hook设置成功");
    } catch(e) {
        console.log("[-] 系统调用级别Socket函数Hook失败: " + e);
    }
    
    console.log("[+] 所有ACB深度Socket监控Hook已设置完成");
    console.log("[*] 开始监控 " + TARGET_HOST + ":" + TARGET_PORT + " 的详细数据...");
    console.log("[*] 监控内容:");
    console.log("    - 目标Socket连接");
    console.log("    - Socket输入输出流");
    console.log("    - 全局输入输出流");
    console.log("    - SSL/TLS数据");
    console.log("    - 系统调用级别数据");
    console.log("[*] 现在请尝试登录操作...");
});

// 数据转换函数
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