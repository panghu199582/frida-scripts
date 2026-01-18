// ios_monitor.js - 高级网络监控脚本
console.log("[*] 高级网络监控脚本已加载");

// 存储所有网络请求和响应
var networkTraffic = [];
var socketMap = new Map(); // 用于跟踪socket连接

// 尝试多种编码解析数据
function tryDecodeData(data, length) {
    var encodings = [
        { name: 'UTF-8', encoding: 4 },
        { name: 'ASCII', encoding: 1 },
        { name: 'Unicode', encoding: 2 },
        { name: 'UTF-16', encoding: 3 },
        { name: 'UTF-16LE', encoding: 5 },
        { name: 'UTF-16BE', encoding: 6 }
    ];
    
    for (var i = 0; i < encodings.length; i++) {
        try {
            var str = ObjC.classes.NSString.alloc().initWithBytes_length_encoding_(
                data,
                length,
                encodings[i].encoding
            ).toString();
            
            // 检查是否是有效的JSON
            try {
                var jsonData = JSON.parse(str);
                return {
                    success: true,
                    encoding: encodings[i].name,
                    data: str,
                    jsonData: jsonData,
                    isJson: true
                };
            } catch(e) {
                // 不是JSON，但至少是有效的字符串
                return {
                    success: true,
                    encoding: encodings[i].name,
                    data: str,
                    isJson: false
                };
            }
        } catch(e) {
            // 这个编码失败，尝试下一个
            continue;
        }
    }
    
    // 所有编码都失败，返回十六进制
    return {
        success: false,
        hexData: hexdump(data)
    };
}

// 格式化JSON数据
function formatJson(jsonData) {
    try {
        return JSON.stringify(jsonData, null, 2);
    } catch(e) {
        return "Error formatting JSON: " + e.message;
    }
}

// 检查是否是HTTP请求
function isHttpRequest(data) {
    var httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
    var firstLine = data.split('\n')[0];
    
    for (var i = 0; i < httpMethods.length; i++) {
        if (firstLine.startsWith(httpMethods[i] + ' ')) {
            return true;
        }
    }
    
    return false;
}

// 解析HTTP请求
function parseHttpRequest(data) {
    try {
        var lines = data.split('\n');
        var firstLine = lines[0];
        var parts = firstLine.split(' ');
        
        var method = parts[0];
        var path = parts[1];
        var version = parts[2];
        
        var headers = {};
        var body = '';
        var headerSection = true;
        
        for (var i = 1; i < lines.length; i++) {
            if (lines[i].trim() === '') {
                headerSection = false;
                continue;
            }
            
            if (headerSection) {
                var headerParts = lines[i].split(':');
                if (headerParts.length >= 2) {
                    var headerName = headerParts[0].trim();
                    var headerValue = headerParts.slice(1).join(':').trim();
                    headers[headerName] = headerValue;
                }
            } else {
                body += lines[i] + '\n';
            }
        }
        
        return {
            method: method,
            path: path,
            version: version,
            headers: headers,
            body: body.trim()
        };
    } catch(e) {
        return null;
    }
}

// 解析HTTP响应
function parseHttpResponse(data) {
    try {
        var lines = data.split('\n');
        var firstLine = lines[0];
        var parts = firstLine.split(' ');
        
        var version = parts[0];
        var statusCode = parseInt(parts[1]);
        var statusText = parts.slice(2).join(' ');
        
        var headers = {};
        var body = '';
        var headerSection = true;
        
        for (var i = 1; i < lines.length; i++) {
            if (lines[i].trim() === '') {
                headerSection = false;
                continue;
            }
            
            if (headerSection) {
                var headerParts = lines[i].split(':');
                if (headerParts.length >= 2) {
                    var headerName = headerParts[0].trim();
                    var headerValue = headerParts.slice(1).join(':').trim();
                    headers[headerName] = headerValue;
                }
            } else {
                body += lines[i] + '\n';
            }
        }
        
        return {
            version: version,
            statusCode: statusCode,
            statusText: statusText,
            headers: headers,
            body: body.trim()
        };
    } catch(e) {
        return null;
    }
}

// 监控socket创建
Interceptor.attach(Module.findExportByName(null, 'socket'), {
        onEnter: function(args) {
        this.domain = args[0].toInt32();
        this.type = args[1].toInt32();
        this.protocol = args[2].toInt32();
    },
    onLeave: function(retval) {
        if (retval.toInt32() > 0) {
            var socketId = retval.toInt32();
            socketMap.set(socketId, {
                domain: this.domain,
                type: this.type,
                protocol: this.protocol,
                created: new Date().toISOString(),
                requests: [],
                responses: [],
                connected: false,
                closed: false
            });
            
            console.log('\n[+] Socket创建: ' + socketId);
            console.log('    域: ' + this.domain + ' (AF_INET=' + 2 + ')');
            console.log('    类型: ' + this.type + ' (SOCK_STREAM=' + 1 + ')');
            console.log('    协议: ' + this.protocol + ' (IPPROTO_TCP=' + 6 + ')');
        }
    }
});

// 监控connect调用
Interceptor.attach(Module.findExportByName(null, 'connect'), {
    onEnter: function(args) {
        this.socketId = args[0].toInt32();
        this.sockaddr = args[1];
        
        // 读取sockaddr结构
        var sa_family = Memory.readU16(this.sockaddr);
        var port = Memory.readU16(this.sockaddr.add(2));
        port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8); // 网络字节序转主机字节序
        
        var addr = Memory.readU32(this.sockaddr.add(4));
        var ip = [
            addr & 0xFF,
            (addr >> 8) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 24) & 0xFF
        ].join('.');
        
        this.port = port;
        this.ip = ip;
    },
    onLeave: function(retval) {
        if (retval.toInt32() === 0) {
            var socketInfo = socketMap.get(this.socketId);
            if (socketInfo) {
                socketInfo.connected = true;
                socketInfo.remotePort = this.port;
                socketInfo.remoteIP = this.ip;
                
                console.log('\n[+] Socket连接: ' + this.socketId);
                console.log('    远程IP: ' + this.ip);
                console.log('    远程端口: ' + this.port);
            }
        }
    }
});

// 监控send调用
Interceptor.attach(Module.findExportByName(null, 'send'), {
                onEnter: function(args) {
        this.socketId = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var length = retval.toInt32();
        if (length > 0) {
            var socketInfo = socketMap.get(this.socketId);
            if (socketInfo) {
                // 尝试读取发送的数据
                var data = Memory.readByteArray(this.buf, length);
                
                // 保存请求
                var request = {
                    time: new Date().toISOString(),
                    length: length,
                    rawData: data
                };
                
                // 尝试解析数据
                var decodedData = tryDecodeData(this.buf, length);
                
                if (decodedData.success) {
                    request.data = decodedData.data;
                    request.encoding = decodedData.encoding;
                    
                    if (decodedData.isJson) {
                        request.jsonData = decodedData.jsonData;
                    }
                    
                    // 检查是否是HTTP请求
                    if (isHttpRequest(decodedData.data)) {
                        request.httpData = parseHttpRequest(decodedData.data);
                    }
                    
                    // 打印请求信息
                    console.log('\n[+] 请求发送 (Socket: ' + this.socketId + '):');
                    console.log('----------------------------------------');
                    console.log('长度:', length);
                    console.log('编码:', decodedData.encoding);
                    
                    if (request.httpData) {
                        console.log('HTTP方法:', request.httpData.method);
                        console.log('路径:', request.httpData.path);
                        console.log('头部:', JSON.stringify(request.httpData.headers, null, 2));
                        console.log('主体:', request.httpData.body);
                    } else if (decodedData.isJson) {
                        console.log('JSON数据:');
                        console.log(formatJson(decodedData.jsonData));
                    } else {
                        console.log('数据:', decodedData.data);
                    }
                    
                    console.log('----------------------------------------');
                } else {
                    // 转换失败，显示十六进制
                    request.hexData = decodedData.hexData;
                    
                    console.log('\n[+] 请求发送 (Socket: ' + this.socketId + ') (HEX):');
                    console.log('----------------------------------------');
                    console.log('长度:', length);
                    console.log(decodedData.hexData);
                    console.log('----------------------------------------');
                }
                
                socketInfo.requests.push(request);
                networkTraffic.push({
                    type: 'request',
                    socketId: this.socketId,
                    time: request.time,
                    data: request
                });
            }
        }
    }
});

// 监控recv调用
Interceptor.attach(Module.findExportByName(null, 'recv'), {
    onEnter: function(args) {
        this.socketId = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var length = retval.toInt32();
        if (length > 0) {
            var socketInfo = socketMap.get(this.socketId);
            if (socketInfo) {
                // 尝试读取接收的数据
                var data = Memory.readByteArray(this.buf, length);
                
                // 保存响应
                var response = {
                    time: new Date().toISOString(),
                    length: length,
                    rawData: data
                };
                
                // 尝试解析数据
                var decodedData = tryDecodeData(this.buf, length);
                
                if (decodedData.success) {
                    response.data = decodedData.data;
                    response.encoding = decodedData.encoding;
                    
                    if (decodedData.isJson) {
                        response.jsonData = decodedData.jsonData;
                    }
                    
                    // 检查是否是HTTP响应
                    if (decodedData.data.startsWith('HTTP/')) {
                        response.httpData = parseHttpResponse(decodedData.data);
                    }
                    
                    // 打印响应信息
                    console.log('\n[+] 响应接收 (Socket: ' + this.socketId + '):');
                    console.log('----------------------------------------');
                    console.log('长度:', length);
                    console.log('编码:', decodedData.encoding);
                    
                    if (response.httpData) {
                        console.log('HTTP状态:', response.httpData.statusCode, response.httpData.statusText);
                        console.log('头部:', JSON.stringify(response.httpData.headers, null, 2));
                        console.log('主体:', response.httpData.body);
                    } else if (decodedData.isJson) {
                        console.log('JSON数据:');
                        console.log(formatJson(decodedData.jsonData));
                    } else {
                        console.log('数据:', decodedData.data);
                    }
                    
                    console.log('----------------------------------------');
                } else {
                    // 转换失败，显示十六进制
                    response.hexData = decodedData.hexData;
                    
                    console.log('\n[+] 响应接收 (Socket: ' + this.socketId + ') (HEX):');
                    console.log('----------------------------------------');
                    console.log('长度:', length);
                    console.log(decodedData.hexData);
                    console.log('----------------------------------------');
                }
                
                socketInfo.responses.push(response);
                networkTraffic.push({
                    type: 'response',
                    socketId: this.socketId,
                    time: response.time,
                    data: response
                });
            }
        }
    }
});

// 监控close调用
Interceptor.attach(Module.findExportByName(null, 'close'), {
    onEnter: function(args) {
        this.socketId = args[0].toInt32();
    },
    onLeave: function(retval) {
        var socketInfo = socketMap.get(this.socketId);
        if (socketInfo) {
            socketInfo.closed = true;
            socketInfo.closedTime = new Date().toISOString();
            
            console.log('\n[+] Socket关闭: ' + this.socketId);
            console.log('    创建时间:', socketInfo.created);
            console.log('    关闭时间:', socketInfo.closedTime);
            console.log('    请求数量:', socketInfo.requests.length);
            console.log('    响应数量:', socketInfo.responses.length);
            
            if (socketInfo.remoteIP) {
                console.log('    远程IP:', socketInfo.remoteIP);
                console.log('    远程端口:', socketInfo.remotePort);
            }
        }
    }
});

// 添加一个函数来查看所有请求
global.showRequests = function() {
    console.log('\n[+] 所有请求 (' + networkTraffic.filter(t => t.type === 'request').length + '):');
    networkTraffic.filter(t => t.type === 'request').forEach((t, i) => {
        var request = t.data;
        console.log('请求 #' + (i+1) + ' (Socket: ' + t.socketId + ') 在 ' + request.time + ' (长度: ' + request.length + ')');
        
        if (request.encoding) {
            console.log('编码:', request.encoding);
        }
        
        if (request.httpData) {
            console.log('HTTP方法:', request.httpData.method);
            console.log('路径:', request.httpData.path);
            console.log('头部:', JSON.stringify(request.httpData.headers, null, 2));
            console.log('主体:', request.httpData.body);
        } else if (request.jsonData) {
            console.log('JSON数据:');
            console.log(formatJson(request.jsonData));
        } else if (request.data) {
            console.log('数据:', request.data);
        } else if (request.hexData) {
            console.log('十六进制数据:');
            console.log(request.hexData);
        }
        
        console.log('----------------------------------------');
    });
};

// 添加一个函数来查看所有响应
global.showResponses = function() {
    console.log('\n[+] 所有响应 (' + networkTraffic.filter(t => t.type === 'response').length + '):');
    networkTraffic.filter(t => t.type === 'response').forEach((t, i) => {
        var response = t.data;
        console.log('响应 #' + (i+1) + ' (Socket: ' + t.socketId + ') 在 ' + response.time + ' (长度: ' + response.length + ')');
        
        if (response.encoding) {
            console.log('编码:', response.encoding);
        }
        
        if (response.httpData) {
            console.log('HTTP状态:', response.httpData.statusCode, response.httpData.statusText);
            console.log('头部:', JSON.stringify(response.httpData.headers, null, 2));
            console.log('主体:', response.httpData.body);
        } else if (response.jsonData) {
            console.log('JSON数据:');
            console.log(formatJson(response.jsonData));
        } else if (response.data) {
            console.log('数据:', response.data);
        } else if (response.hexData) {
            console.log('十六进制数据:');
            console.log(response.hexData);
        }
        
        console.log('----------------------------------------');
    });
};

// 添加一个函数来查看请求的十六进制数据
global.showRequestHex = function(index) {
    var requests = networkTraffic.filter(t => t.type === 'request');
    if (index > 0 && index <= requests.length) {
        var request = requests[index-1].data;
        console.log('\n[+] 请求 #' + index + ' 十六进制数据:');
        console.log(request.hexData || '无十六进制数据可用');
    } else {
        console.log('无效的请求索引');
    }
};

// 添加一个函数来查看响应的十六进制数据
global.showResponseHex = function(index) {
    var responses = networkTraffic.filter(t => t.type === 'response');
    if (index > 0 && index <= responses.length) {
        var response = responses[index-1].data;
        console.log('\n[+] 响应 #' + index + ' 十六进制数据:');
        console.log(response.hexData || '无十六进制数据可用');
    } else {
        console.log('无效的响应索引');
    }
};

// 添加一个函数来清空请求和响应
global.clearAll = function() {
    networkTraffic = [];
    socketMap.clear();
    console.log('所有网络流量数据已清空');
};

// 添加一个函数来导出所有数据
global.exportData = function() {
    var exportData = {
        networkTraffic: networkTraffic,
        sockets: Array.from(socketMap.entries()).map(([id, info]) => ({
            id: id,
            info: info
        }))
    };
    console.log(JSON.stringify(exportData, null, 2));
};

// 添加一个函数来过滤请求
global.filterRequests = function(keyword) {
    console.log('\n[+] 过滤包含 "' + keyword + '" 的请求');
    var count = 0;
    
    networkTraffic.filter(t => t.type === 'request').forEach((t, i) => {
        var request = t.data;
        var match = false;
        
        if (request.data && request.data.includes(keyword)) {
            match = true;
        } else if (request.httpData && request.httpData.path.includes(keyword)) {
            match = true;
        }
        
        if (match) {
            count++;
            console.log('请求 #' + (i+1) + ' (Socket: ' + t.socketId + ') 在 ' + request.time + ' (长度: ' + request.length + ')');
            
            if (request.encoding) {
                console.log('编码:', request.encoding);
            }
            
            if (request.httpData) {
                console.log('HTTP方法:', request.httpData.method);
                console.log('路径:', request.httpData.path);
                console.log('头部:', JSON.stringify(request.httpData.headers, null, 2));
                console.log('主体:', request.httpData.body);
            } else if (request.jsonData) {
                console.log('JSON数据:');
                console.log(formatJson(request.jsonData));
            } else if (request.data) {
                console.log('数据:', request.data);
            }
            
            console.log('----------------------------------------');
        }
    });
    
    console.log('找到 ' + count + ' 个匹配的请求');
};

// 添加一个函数来过滤响应
global.filterResponses = function(keyword) {
    console.log('\n[+] 过滤包含 "' + keyword + '" 的响应');
    var count = 0;
    
    networkTraffic.filter(t => t.type === 'response').forEach((t, i) => {
        var response = t.data;
        var match = false;
        
        if (response.data && response.data.includes(keyword)) {
            match = true;
        } else if (response.httpData && response.httpData.body.includes(keyword)) {
            match = true;
        }
        
        if (match) {
            count++;
            console.log('响应 #' + (i+1) + ' (Socket: ' + t.socketId + ') 在 ' + response.time + ' (长度: ' + response.length + ')');
            
            if (response.encoding) {
                console.log('编码:', response.encoding);
            }
            
            if (response.httpData) {
                console.log('HTTP状态:', response.httpData.statusCode, response.httpData.statusText);
                console.log('头部:', JSON.stringify(response.httpData.headers, null, 2));
                console.log('主体:', response.httpData.body);
            } else if (response.jsonData) {
                console.log('JSON数据:');
                console.log(formatJson(response.jsonData));
            } else if (response.data) {
                console.log('数据:', response.data);
            }
            
            console.log('----------------------------------------');
        }
    });
    
    console.log('找到 ' + count + ' 个匹配的响应');
};

// 添加一个函数来查看所有socket
global.showSockets = function() {
    console.log('\n[+] 所有Socket (' + socketMap.size + '):');
    socketMap.forEach((info, id) => {
        console.log('Socket #' + id + ':');
        console.log('  创建时间:', info.created);
        console.log('  状态:', info.closed ? '已关闭' : (info.connected ? '已连接' : '未连接'));
        console.log('  关闭时间:', info.closedTime || '未关闭');
        console.log('  请求数量:', info.requests.length);
        console.log('  响应数量:', info.responses.length);
        
        if (info.remoteIP) {
            console.log('  远程IP:', info.remoteIP);
            console.log('  远程端口:', info.remotePort);
        }
        
        console.log('----------------------------------------');
    });
};

// 添加一个函数来查看特定socket的流量
global.showSocketTraffic = function(socketId) {
    var socketInfo = socketMap.get(parseInt(socketId));
    if (socketInfo) {
        console.log('\n[+] Socket #' + socketId + ' 流量:');
        console.log('创建时间:', socketInfo.created);
        console.log('状态:', socketInfo.closed ? '已关闭' : (socketInfo.connected ? '已连接' : '未连接'));
        console.log('关闭时间:', socketInfo.closedTime || '未关闭');
        
        if (socketInfo.remoteIP) {
            console.log('远程IP:', socketInfo.remoteIP);
            console.log('远程端口:', socketInfo.remotePort);
        }
        
        console.log('\n请求 (' + socketInfo.requests.length + '):');
        socketInfo.requests.forEach((request, i) => {
            console.log('请求 #' + (i+1) + ' 在 ' + request.time + ' (长度: ' + request.length + ')');
            
            if (request.encoding) {
                console.log('编码:', request.encoding);
            }
            
            if (request.httpData) {
                console.log('HTTP方法:', request.httpData.method);
                console.log('路径:', request.httpData.path);
                console.log('头部:', JSON.stringify(request.httpData.headers, null, 2));
                console.log('主体:', request.httpData.body);
            } else if (request.jsonData) {
                console.log('JSON数据:');
                console.log(formatJson(request.jsonData));
            } else if (request.data) {
                console.log('数据:', request.data);
            } else if (request.hexData) {
                console.log('十六进制数据:');
                console.log(request.hexData);
            }
            
            console.log('----------------------------------------');
        });
        
        console.log('\n响应 (' + socketInfo.responses.length + '):');
        socketInfo.responses.forEach((response, i) => {
            console.log('响应 #' + (i+1) + ' 在 ' + response.time + ' (长度: ' + response.length + ')');
            
            if (response.encoding) {
                console.log('编码:', response.encoding);
            }
            
            if (response.httpData) {
                console.log('HTTP状态:', response.httpData.statusCode, response.httpData.statusText);
                console.log('头部:', JSON.stringify(response.httpData.headers, null, 2));
                console.log('主体:', response.httpData.body);
            } else if (response.jsonData) {
                console.log('JSON数据:');
                console.log(formatJson(response.jsonData));
            } else if (response.data) {
                console.log('数据:', response.data);
            } else if (response.hexData) {
                console.log('十六进制数据:');
                console.log(response.hexData);
            }
            
            console.log('----------------------------------------');
        });
    } else {
        console.log('未找到Socket #' + socketId);
    }
};

// 添加一个函数来保存所有数据到文件
global.saveToFile = function(filename) {
    var exportData = {
        networkTraffic: networkTraffic,
        sockets: Array.from(socketMap.entries()).map(([id, info]) => ({
            id: id,
            info: info
        }))
    };
    
    var data = JSON.stringify(exportData, null, 2);
    var file = new File(filename, "w");
    file.write(data);
    file.flush();
    file.close();
    
    console.log('数据已保存到文件: ' + filename);
};

console.log("[*] 高级网络监控已安装");
console.log("[*] 使用 'showRequests()' 查看所有请求");
console.log("[*] 使用 'showResponses()' 查看所有响应");
console.log("[*] 使用 'showRequestHex(index)' 查看请求的十六进制数据");
console.log("[*] 使用 'showResponseHex(index)' 查看响应的十六进制数据");
console.log("[*] 使用 'filterRequests(keyword)' 按关键字过滤请求");
console.log("[*] 使用 'filterResponses(keyword)' 按关键字过滤响应");
console.log("[*] 使用 'showSockets()' 查看所有Socket");
console.log("[*] 使用 'showSocketTraffic(socketId)' 查看特定Socket的流量");
console.log("[*] 使用 'clearAll()' 清空所有捕获的数据");
console.log("[*] 使用 'exportData()' 导出所有数据为JSON");
console.log("[*] 使用 'saveToFile(filename)' 保存所有数据到文件");