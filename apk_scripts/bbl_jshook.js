// 添加一个全局的日志函数
function log(message) {
    try {
        console.log("[BBL_DEBUG] " + message);
        Java.perform(function() {
            var Log = Java.use("android.util.Log");
            Log.d("BBL_DEBUG", message);
        });
    } catch(e) {
        console.log("[BBL_ERROR] Failed to log: " + e);
    }
}

// 在脚本开始时输出标记
log("=== BBL JSHook Script Started ===");

// 添加错误处理
try {
    Java.perform(function() {
        log("Script started");

        // 检查进程名
        var Process = Java.use("android.os.Process");
        var currentPid = Process.myPid();
        log("Current process ID: " + currentPid);

        // 检查包名
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();
        var packageName = context.getPackageName();
        log("Current package name: " + packageName);

        // Hook bx.Mtz 类
        try {
            var bxMtz = Java.use("bx.Mtz");
            log("Found bx.Mtz class");
            
            // Hook LUk 方法
            bxMtz.LUk.implementation = function() {
                try {
                    log("=== bx.Mtz.LUk called ===");
                    
                    // 获取调用栈
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    log("Call stack:");
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                    
                    // 获取所有字段的值
                    var fields = this.getClass().getDeclaredFields();
                    for (var i = 0; i < fields.length; i++) {
                        fields[i].setAccessible(true);
                        var value = fields[i].get(this);
                        log("Field: " + fields[i].getName() + " = " + value);
                    }
                    
                    var result = this.LUk();
                    log("Result: " + result);
                    return result;
                } catch(e) {
                    log("Error in LUk: " + e);
                    return this.LUk();
                }
            };
            
            // Hook mKj 方法
            bxMtz.mKj.overload('okhttp3.Request$Builder').implementation = function(builder) {
                try {
                    log("=== bx.Mtz.mKj called ===");
                    log("Builder: " + builder);
                    
                    // 获取调用栈
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    log("Call stack:");
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                    
                    var result = this.mKj(builder);
                    log("Result: " + result);
                    return result;
                } catch(e) {
                    log("Error in mKj: " + e);
                    return this.mKj(builder);
                }
            };
        } catch(e) {
            log("bx.Mtz hook failed: " + e);
        }

        // Hook bx.epT 类
        try {
            var bxEpT = Java.use("bx.epT");
            log("Found bx.epT class");
            
            // Hook invoke 方法
            bxEpT.invoke.implementation = function() {
                try {
                    log("=== bx.epT.invoke called ===");
                    
                    // 获取调用栈
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    log("Call stack:");
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                    
                    var result = this.invoke.apply(this, arguments);
                    log("Result: " + result);
                    return result;
                } catch(e) {
                    log("Error in invoke: " + e);
                    return this.invoke.apply(this, arguments);
                }
            };
        } catch(e) {
            log("bx.epT hook failed: " + e);
        }

        // Hook Request.Builder 类
        try {
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            log("Found Request.Builder class");
            
            // Hook addHeader 方法
            RequestBuilder.addHeader.implementation = function(name, value) {
                try {
                    log("=== Request.Builder.addHeader called ===");
                    log("Header Name: " + name);
                    log("Header Value: " + value);
                    
                    // 获取调用栈
                    var Exception = Java.use("java.lang.Exception");
                    var stackTrace = Exception.$new().getStackTrace();
                    log("Call stack:");
                    for (var i = 0; i < stackTrace.length; i++) {
                        log("  at " + stackTrace[i].toString());
                    }
                    
                    // 调用原始方法
                    return this.addHeader(name, value);
                } catch(e) {
                    log("Error in addHeader: " + e);
                    return this.addHeader(name, value);
                }
            };
            
            // Hook build 方法
            RequestBuilder.build.implementation = function() {
                try {
                    log("=== Request.Builder.build called ===");
                    var request = this.build();
                    log("Built Request URL: " + request.url().toString());
                    log("Built Request Method: " + request.method());
                    
                    // Log headers
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        log("Built Request Header: " + name + " = " + value);
                    }
                    
                    return request;
                } catch(e) {
                    log("Error in build: " + e);
                    return this.build();
                }
            };
        } catch(e) {
            log("Request.Builder hook failed: " + e);
        }

        // Hook OkHttp 相关代码
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            log("Found OkHttpClient class");
            
            // Hook CallServerInterceptor
            var CallServerInterceptor = Java.use("okhttp3.internal.http.CallServerInterceptor");
            CallServerInterceptor.intercept.implementation = function(chain) {
                try {
                    log("=== Final Request Phase ===");
                    var request = chain.request();
                    log("Request URL: " + request.url().toString());
                    log("Request Method: " + request.method());
                    
                    // Log request headers
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        log("Request Header: " + name + " = " + value);
                    }
                    
                    // Log request body
                    var body = request.body();
                    if (body) {
                        var buffer = Java.use("okio.Buffer").$new();
                        body.writeTo(buffer);
                        const bodyStr = buffer.readUtf8();
                        log("Request Body: " + bodyStr);
                    }
                    
                    var response = this.intercept(chain);
                    log("=== Response Phase ===");
                    log("Response Code: " + response.code());
                    
                    // Log response headers
                    var responseHeaders = response.headers();
                    for (var i = 0; i < responseHeaders.size(); i++) {
                        var name = responseHeaders.name(i);
                        var value = responseHeaders.value(i);
                        log("Response Header: " + name + " = " + value);
                    }
                    
                    return response;
                } catch(e) {
                    log("Error in CallServerInterceptor: " + e);
                    return this.intercept(chain);
                }
            };
        } catch(e) {
            log("OkHttp hook failed: " + e);
        }
        
        log("All hooks installed successfully");
    });
} catch(e) {
    log("Fatal error in script: " + e);
} 