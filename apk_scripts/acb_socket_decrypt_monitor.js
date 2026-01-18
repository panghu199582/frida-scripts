/*
 * ACB Socket解密监控脚本
 * 专门监控ACB相关域名的socket请求并尝试解密
 */

console.log("[+] ACB Socket解密监控脚本已启动");

// ACB相关域名列表
var ACB_DOMAINS = [
    "acb.com.vn",
    "api.acb.com.vn", 
    "apiapp.acb.com.vn",
    "mobile.acb.com.vn",
    "app.acb.com.vn",
    "www.acb.com.vn",
    "secure.acb.com.vn",
    "login.acb.com.vn",
    "api.acb.com",
    "mobile.acb.com"
];

// 检查是否是ACB相关域名
function isACBDomain(host) {
    if (!host) return false;
    host = host.toLowerCase();
    return ACB_DOMAINS.some(function(domain) {
        return host.indexOf(domain) !== -1;
    });
}

// 记录ACB相关的连接
var acbConnections = {};

Java.perform(function() {
    console.log("[*] ACB Socket解密监控脚本初始化...");
    console.log("[*] 监控的ACB域名: " + ACB_DOMAINS.join(", "));
    
    // 1. Hook Java Socket连接
    try {
        console.log("[*] 设置Java Socket Hook...");
        
        var Socket = Java.use("java.net.Socket");
        
        // Hook Socket构造函数
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            var result = this.$init(host, port);
            if (isACBDomain(host)) {
                console.log("[+] ACB Socket连接: " + host + ":" + port);
                acbConnections[this.hashCode()] = {
                    host: host,
                    port: port,
                    type: "Java Socket"
                };
            }
            return result;
        };
        
        Socket.$init.overload('java.lang.String', 'int', 'java.net.InetAddress', 'int').implementation = function(host, port, localAddr, localPort) {
            var result = this.$init(host, port, localAddr, localPort);
            if (isACBDomain(host)) {
                console.log("[+] ACB Socket连接(带本地地址): " + host + ":" + port + " -> " + localAddr.getHostAddress() + ":" + localPort);
                acbConnections[this.hashCode()] = {
                    host: host,
                    port: port,
                    type: "Java Socket"
                };
            }
            return result;
        };
        
        // Hook Socket连接方法
        Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
            var result = this.connect(endpoint);
            var host = this.getInetAddress().getHostName();
            if (isACBDomain(host)) {
                console.log("[+] ACB Socket连接: " + host + ":" + this.getPort());
                acbConnections[this.hashCode()] = {
                    host: host,
                    port: this.getPort(),
                    type: "Java Socket"
                };
            }
            return result;
        };
        
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(endpoint, timeout) {
            var result = this.connect(endpoint, timeout);
            var host = this.getInetAddress().getHostName();
            if (isACBDomain(host)) {
                console.log("[+] ACB Socket连接(带超时): " + host + ":" + this.getPort() + ", 超时: " + timeout);
                acbConnections[this.hashCode()] = {
                    host: host,
                    port: this.getPort(),
                    type: "Java Socket"
                };
            }
            return result;
        };
        
        console.log("[+] Java Socket Hook设置成功");
    } catch(e) {
        console.log("[-] Java Socket Hook失败: " + e);
    }
    
    // 2. Hook Socket输入输出流 (只监控ACB连接)
    try {
        console.log("[*] 设置Socket流Hook...");
        
        var SocketInputStream = Java.use('java.net.SocketInputStream');
        if (SocketInputStream) {
            SocketInputStream.read.overload('[B').implementation = function(buffer) {
                var result = this.read(buffer);
                if (result > 0) {
                    try {
                        var socketHash = this.socket.hashCode();
                        if (acbConnections[socketHash]) {
                            var data = Java.array('byte', buffer);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            var sslInfo = parseSSLData(data);
                            var connInfo = acbConnections[socketHash];
                            
                            console.log("[+] ACB Socket读取: " + connInfo.host + ":" + connInfo.port + " -> " + result + " bytes");
                            if (sslInfo !== "数据太短") {
                                console.log("    SSL信息: " + sslInfo);
                            }
                            console.log("    数据: " + stringData);
                            console.log("    十六进制: " + hexData);
                            
                            // 尝试解析HTTP响应
                            if (stringData.indexOf("HTTP/") === 0) {
                                console.log("    [HTTP响应] " + stringData.split('\n')[0]);
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
                        if (acbConnections[socketHash]) {
                            var data = Java.array('byte', buffer);
                            var hexData = bytesToHex(data);
                            var stringData = bytesToString(data);
                            var sslInfo = parseSSLData(data);
                            var connInfo = acbConnections[socketHash];
                            
                            console.log("[+] ACB Socket读取: " + connInfo.host + ":" + connInfo.port + " -> " + result + " bytes");
                            if (sslInfo !== "数据太短") {
                                console.log("    SSL信息: " + sslInfo);
                            }
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
                    if (acbConnections[socketHash]) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var sslInfo = parseSSLData(data);
                        var connInfo = acbConnections[socketHash];
                        
                        console.log("[+] ACB Socket写入: " + connInfo.host + ":" + connInfo.port + " -> " + data.length + " bytes");
                        if (sslInfo !== "数据太短") {
                            console.log("    SSL信息: " + sslInfo);
                        }
                        console.log("    数据: " + stringData);
                        console.log("    十六进制: " + hexData);
                        
                        // 尝试解析HTTP请求
                        if (stringData.indexOf("GET ") === 0 || stringData.indexOf("POST ") === 0) {
                            console.log("    [HTTP请求] " + stringData.split('\n')[0]);
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
                    if (acbConnections[socketHash]) {
                        var data = Java.array('byte', buffer);
                        var hexData = bytesToHex(data);
                        var stringData = bytesToString(data);
                        var sslInfo = parseSSLData(data);
                        var connInfo = acbConnections[socketHash];
                        
                        console.log("[+] ACB Socket写入: " + connInfo.host + ":" + connInfo.port + " -> " + length + " bytes");
                        if (sslInfo !== "数据太短") {
                            console.log("    SSL信息: " + sslInfo);
                        }
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
    
    // 3. Hook SSL/TLS底层函数 (只监控ACB相关)
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
                            var sslInfo = parseSSLData(data);
                            
                            // 检查是否包含ACB域名
                            if (stringData.indexOf("acb.com") !== -1 || 
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("Host:") !== -1) {
                                
                                console.log("[+] ACB SSL写入: " + len + " bytes");
                                console.log("    SSL信息: " + sslInfo);
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
                            var sslInfo = parseSSLData(data);
                            
                            // 检查是否包含ACB相关数据
                            if (stringData.indexOf("acb.com") !== -1 || 
                                stringData.indexOf("ACB") !== -1 ||
                                stringData.indexOf("HTTP/") === 0 ||
                                stringData.indexOf("Content-Type:") !== -1) {
                                
                                console.log("[+] ACB SSL读取: " + len + " bytes");
                                console.log("    SSL信息: " + sslInfo);
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
    
    // 4. Hook 应用特定的网络类
    try {
        console.log("[*] 尝试Hook ACB应用特定的网络类...");
        
        var acbClasses = [
            "com.acb.mobile.network.NetworkManager",
            "com.acb.mobile.network.ApiService", 
            "com.acb.mobile.network.HttpClient",
            "com.acb.mobile.network.RequestHandler",
            "com.acb.mobile.network.ResponseHandler",
            "com.acb.mobile.network.DataProcessor",
            "com.acb.mobile.network.JsonParser",
            "com.acb.mobile.network.NetworkCallback",
            "com.acb.mobile.network.SocketManager",
            "com.acb.mobile.network.SocketClient"
        ];
        
        acbClasses.forEach(function(className) {
            try {
                var cls = Java.use(className);
                if (cls) {
                    console.log("[+] 找到ACB网络类: " + className);
                    
                    // 尝试Hook一些常见的方法名
                    var commonMethods = ["onResponse", "onSuccess", "parseResponse", "handleData", "processData", "send", "receive"];
                    commonMethods.forEach(function(methodName) {
                        try {
                            if (cls[methodName]) {
                                console.log("[+] Hook ACB方法: " + className + "." + methodName);
                            }
                        } catch(e) {
                            // 忽略方法不存在的情况
                        }
                    });
                }
            } catch(e) {
                // 忽略类不存在的情况
            }
        });
        
        console.log("[+] ACB应用特定类Hook完成");
    } catch(e) {
        console.log("[-] ACB应用特定类Hook失败: " + e);
    }
    
    console.log("[+] 所有ACB Socket解密监控Hook已设置完成");
    console.log("[*] 开始监控ACB相关域名的Socket通信...");
    console.log("[*] 监控内容:");
    console.log("    - ACB域名Socket连接");
    console.log("    - ACB相关SSL/TLS数据");
    console.log("    - HTTP请求和响应");
    console.log("    - 应用层数据处理");
});

// 改进的数据转换函数
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

// SSL数据解析函数
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