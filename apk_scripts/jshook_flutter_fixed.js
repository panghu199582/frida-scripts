console.log("[+] Flutter 修复版网络抓包脚本启动");

// 统一日志格式
function logNetwork(type, data) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${type}] ${data}`);
}

// 安全的hook函数
function safeHook(className, methodName, callback) {
    try {
        const clazz = Java.use(className);
        if (clazz && clazz[methodName]) {
            clazz[methodName].implementation = callback;
            logNetwork("HOOK", `成功hook ${className}.${methodName}`);
            return true;
        }
    } catch (e) {
        logNetwork("ERROR", `Hook ${className}.${methodName} 失败: ${e.message}`);
    }
    return false;
}

// Hook HttpURLConnection (已确认可用)
function hookHttpURLConnection() {
    logNetwork("INFO", "开始hook HttpURLConnection...");
    
    // Hook getInputStream
    safeHook("java.net.HttpURLConnection", "getInputStream", function() {
        try {
            logNetwork("REQUEST", "=== HttpURLConnection 请求 ===");
            logNetwork("URL", this.getURL().toString());
            logNetwork("METHOD", this.getRequestMethod());
            
            // 请求头
            const requestProperties = this.getRequestProperties();
            if (requestProperties) {
                logNetwork("REQUEST_HEADERS", "请求头:");
                const keys = requestProperties.keySet().toArray();
                for (let i = 0; i < keys.length; i++) {
                    const key = keys[i];
                    const value = requestProperties.get(key);
                    logNetwork("HEADER", `${key}: ${value}`);
                }
            }
            
        } catch (e) {
            logNetwork("ERROR", `HttpURLConnection hook错误: ${e.message}`);
        }
        
        return this.getInputStream();
    });
    
    // Hook getOutputStream
    safeHook("java.net.HttpURLConnection", "getOutputStream", function() {
        try {
            logNetwork("REQUEST", "=== HttpURLConnection POST请求 ===");
            logNetwork("URL", this.getURL().toString());
            logNetwork("METHOD", this.getRequestMethod());
        } catch (e) {
            logNetwork("ERROR", `HttpURLConnection getOutputStream hook错误: ${e.message}`);
        }
        
        return this.getOutputStream();
    });
}

// Hook URL.openConnection (修复重载问题)
function hookURL() {
    logNetwork("INFO", "开始hook URL.openConnection...");
    
    try {
        const URLClass = Java.use("java.net.URL");
        
        // Hook 无参数版本
        URLClass.openConnection.overload().implementation = function() {
            try {
                logNetwork("URL", `URL.openConnection(): ${this.toString()}`);
            } catch (e) {
                logNetwork("ERROR", `URL.openConnection() hook错误: ${e.message}`);
            }
            
            return this.openConnection();
        };
        
        // Hook 带Proxy参数版本
        URLClass.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
            try {
                logNetwork("URL", `URL.openConnection(proxy): ${this.toString()}`);
            } catch (e) {
                logNetwork("ERROR", `URL.openConnection(proxy) hook错误: ${e.message}`);
            }
            
            return this.openConnection(proxy);
        };
        
        logNetwork("HOOK", "成功hook java.net.URL.openConnection (所有重载)");
    } catch (e) {
        logNetwork("ERROR", `URL.openConnection hook失败: ${e.message}`);
    }
}

// Hook Socket (Flutter可能使用原生Socket)
function hookSocket() {
    logNetwork("INFO", "开始hook Socket...");
    
    safeHook("java.net.Socket", "getInputStream", function() {
        try {
            logNetwork("SOCKET", `Socket连接: ${this.getInetAddress()}:${this.getPort()}`);
        } catch (e) {
            logNetwork("ERROR", `Socket hook错误: ${e.message}`);
        }
        
        return this.getInputStream();
    });
    
    safeHook("java.net.Socket", "getOutputStream", function() {
        try {
            logNetwork("SOCKET", `Socket输出: ${this.getInetAddress()}:${this.getPort()}`);
        } catch (e) {
            logNetwork("ERROR", `Socket输出hook错误: ${e.message}`);
        }
        
        return this.getOutputStream();
    });
}

// Hook InputStream 读取 (修复重载问题)
function hookInputStream() {
    logNetwork("INFO", "开始hook InputStream...");
    
    try {
        const InputStreamClass = Java.use("java.io.InputStream");
        
        // Hook read() - 无参数
        InputStreamClass.read.overload().implementation = function() {
            try {
                const result = this.read();
                if (result !== -1) {
                    logNetwork("READ", `InputStream读取字节: ${result}`);
                }
            } catch (e) {
                // 忽略错误
            }
            
            return result;
        };
        
        // Hook read(byte[]) - 读取到字节数组
        InputStreamClass.read.overload('[B').implementation = function(buffer) {
            try {
                const result = this.read(buffer);
                if (result > 0) {
                    logNetwork("READ", `InputStream读取字节数组: ${result} 字节`);
                }
            } catch (e) {
                // 忽略错误
            }
            
            return result;
        };
        
        // Hook read(byte[], int, int) - 读取到字节数组的指定位置
        InputStreamClass.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
            try {
                const result = this.read(buffer, offset, length);
                if (result > 0) {
                    logNetwork("READ", `InputStream读取字节数组: ${result} 字节 (offset=${offset}, length=${length})`);
                }
            } catch (e) {
                // 忽略错误
            }
            
            return result;
        };
        
        logNetwork("HOOK", "成功hook java.io.InputStream.read (所有重载)");
    } catch (e) {
        logNetwork("ERROR", `InputStream.read hook失败: ${e.message}`);
    }
}

// Hook OutputStream 写入 (修复重载问题)
function hookOutputStream() {
    logNetwork("INFO", "开始hook OutputStream...");
    
    try {
        const OutputStreamClass = Java.use("java.io.OutputStream");
        
        // Hook write(int) - 写入单个字节
        OutputStreamClass.write.overload('int').implementation = function(b) {
            try {
                logNetwork("WRITE", `OutputStream写入字节: ${b}`);
            } catch (e) {
                // 忽略错误
            }
            
            return this.write(b);
        };
        
        // Hook write(byte[]) - 写入字节数组
        OutputStreamClass.write.overload('[B').implementation = function(data) {
            try {
                if (data && data.length > 0) {
                    logNetwork("WRITE", `OutputStream写入字节数组: ${data.length} 字节`);
                }
            } catch (e) {
                // 忽略错误
            }
            
            return this.write(data);
        };
        
        // Hook write(byte[], int, int) - 写入字节数组的指定部分
        OutputStreamClass.write.overload('[B', 'int', 'int').implementation = function(data, offset, length) {
            try {
                if (data && length > 0) {
                    logNetwork("WRITE", `OutputStream写入字节数组: ${length} 字节 (offset=${offset})`);
                }
            } catch (e) {
                // 忽略错误
            }
            
            return this.write(data, offset, length);
        };
        
        logNetwork("HOOK", "成功hook java.io.OutputStream.write (所有重载)");
    } catch (e) {
        logNetwork("ERROR", `OutputStream.write hook失败: ${e.message}`);
    }
}

// 主函数
function main() {
    logNetwork("INFO", "Flutter 修复版网络抓包脚本初始化...");
    
    // 延迟执行，确保应用完全加载
    setTimeout(function() {
        hookHttpURLConnection();
        hookURL();
        hookSocket();
        hookInputStream();
        hookOutputStream();
        
        logNetwork("INFO", "所有hook设置完成，开始监听网络请求...");
        logNetwork("INFO", "监控的网络库: HttpURLConnection, URL, Socket, InputStream, OutputStream");
    }, 2000);
}

// 启动脚本
main(); 