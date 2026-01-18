console.log("[+] Flutter OkHttp3 网络抓包脚本启动");

// 统一日志格式
function logNetwork(type, data) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${type}] ${data}`);
}

// 安全的类查找函数
function findClassSafely(className, maxSearch = 10) {
    try {
        return Java.use(className);
    } catch (e) {
        logNetwork("ERROR", `类 ${className} 未找到: ${e.message}`);
        return null;
    }
}

// 安全的hook函数
function safeHook(className, methodName, callback) {
    try {
        const clazz = findClassSafely(className);
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

// 解析请求体
function parseRequestBody(body) {
    if (!body) return "无请求体";
    try {
        if (typeof body === 'string') return body;
        if (body.toString) return body.toString();
        return JSON.stringify(body);
    } catch (e) {
        return "请求体解析失败";
    }
}

// 解析响应体
function parseResponseBody(response) {
    if (!response) return "无响应体";
    try {
        if (response.body) {
            const bodyString = response.body.string();
            return bodyString;
        }
        return response.toString();
    } catch (e) {
        return "响应体解析失败";
    }
}

// Hook OkHttp3 核心类
function hookOkHttp3() {
    logNetwork("INFO", "开始hook OkHttp3...");
    
    // Hook OkHttpClient.newCall
    safeHook("okhttp3.OkHttpClient", "newCall", function(request) {
        try {
            logNetwork("REQUEST", "=== OkHttp3 请求开始 ===");
            logNetwork("URL", request.url().toString());
            logNetwork("METHOD", request.method());
            
            // 请求头
            const headers = request.headers();
            if (headers) {
                logNetwork("REQUEST_HEADERS", "请求头:");
                for (let i = 0; i < headers.size(); i++) {
                    const name = headers.name(i);
                    const value = headers.value(i);
                    logNetwork("HEADER", `${name}: ${value}`);
                }
            }
            
            // 请求体
            const body = request.body();
            if (body) {
                const bodyString = parseRequestBody(body);
                logNetwork("REQUEST_BODY", bodyString);
            }
            
        } catch (e) {
            logNetwork("ERROR", `OkHttp3 newCall hook错误: ${e.message}`);
        }
        
        return this.newCall(request);
    });
    
    // Hook Response
    safeHook("okhttp3.Response", "body", function() {
        try {
            const response = this;
            logNetwork("RESPONSE", "=== OkHttp3 响应开始 ===");
            logNetwork("STATUS", `状态码: ${response.code()}`);
            logNetwork("MESSAGE", `状态消息: ${response.message()}`);
            
            // 响应头
            const headers = response.headers();
            if (headers) {
                logNetwork("RESPONSE_HEADERS", "响应头:");
                for (let i = 0; i < headers.size(); i++) {
                    const name = headers.name(i);
                    const value = headers.value(i);
                    logNetwork("HEADER", `${name}: ${value}`);
                }
            }
            
            // 响应体
            const body = response.body();
            if (body) {
                const bodyString = parseResponseBody(response);
                logNetwork("RESPONSE_BODY", bodyString);
            }
            
        } catch (e) {
            logNetwork("ERROR", `OkHttp3 Response hook错误: ${e.message}`);
        }
        
        return this.body();
    });
    
    // Hook Call.execute
    safeHook("okhttp3.Call", "execute", function() {
        try {
            logNetwork("CALL", "OkHttp3 Call.execute 被调用");
        } catch (e) {
            logNetwork("ERROR", `OkHttp3 Call.execute hook错误: ${e.message}`);
        }
        
        return this.execute();
    });
}

// Hook HttpURLConnection (Flutter可能也会使用)
function hookHttpURLConnection() {
    logNetwork("INFO", "开始hook HttpURLConnection...");
    
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
}

// Hook URL.openConnection
function hookURL() {
    logNetwork("INFO", "开始hook URL.openConnection...");
    
    safeHook("java.net.URL", "openConnection", function() {
        try {
            logNetwork("URL", `URL.openConnection: ${this.toString()}`);
        } catch (e) {
            logNetwork("ERROR", `URL.openConnection hook错误: ${e.message}`);
        }
        
        return this.openConnection();
    });
}

// 主函数
function main() {
    logNetwork("INFO", "Flutter OkHttp3 网络抓包脚本初始化...");
    
    // 延迟执行，确保应用完全加载
    setTimeout(function() {
        hookOkHttp3();
        hookHttpURLConnection();
        hookURL();
        
        logNetwork("INFO", "所有hook设置完成，开始监听网络请求...");
    }, 2000);
}

// 启动脚本
main(); 