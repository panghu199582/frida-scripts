/*
 * 混淆类名查找脚本
 * 用于查找被ProGuard/R8混淆后的网络库类名
 */

console.log("[+] 开始搜索混淆后的网络库类...");

// 搜索所有已加载的类
function searchAllClasses() {
    var foundClasses = {
        okhttp: [],
        retrofit: [],
        okio: [],
        http: [],
        network: [],
        socket: [],
        json: []
    };
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // 搜索OkHttp相关类
            if (className.indexOf("okhttp") !== -1 || 
                className.indexOf("OkHttp") !== -1 ||
                className.indexOf("okhttp3") !== -1) {
                foundClasses.okhttp.push(className);
            }
            
            // 搜索Retrofit相关类
            if (className.indexOf("retrofit") !== -1 || 
                className.indexOf("Retrofit") !== -1) {
                foundClasses.retrofit.push(className);
            }
            
            // 搜索Okio相关类
            if (className.indexOf("okio") !== -1 || 
                className.indexOf("Okio") !== -1) {
                foundClasses.okio.push(className);
            }
            
            // 搜索HTTP相关类
            if (className.indexOf("HttpURLConnection") !== -1 ||
                className.indexOf("HttpClient") !== -1 ||
                className.indexOf("HttpRequest") !== -1 ||
                className.indexOf("HttpResponse") !== -1) {
                foundClasses.http.push(className);
            }
            
            // 搜索网络相关类
            if (className.indexOf("Network") !== -1 ||
                className.indexOf("network") !== -1 ||
                className.indexOf("URL") !== -1 ||
                className.indexOf("Url") !== -1) {
                foundClasses.network.push(className);
            }
            
            // 搜索Socket相关类
            if (className.indexOf("Socket") !== -1 ||
                className.indexOf("socket") !== -1) {
                foundClasses.socket.push(className);
            }
            
            // 搜索JSON相关类
            if (className.indexOf("JSON") !== -1 ||
                className.indexOf("json") !== -1 ||
                className.indexOf("Gson") !== -1) {
                foundClasses.json.push(className);
            }
        },
        onComplete: function() {
            console.log("[+] 类搜索完成");
            console.log("");
            
            // 打印结果
            console.log("========== 找到的OkHttp相关类 ==========");
            foundClasses.okhttp.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的Retrofit相关类 ==========");
            foundClasses.retrofit.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的Okio相关类 ==========");
            foundClasses.okio.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的HTTP相关类 ==========");
            foundClasses.http.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的网络相关类 ==========");
            foundClasses.network.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的Socket相关类 ==========");
            foundClasses.socket.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            console.log("========== 找到的JSON相关类 ==========");
            foundClasses.json.forEach(function(className) {
                console.log("  " + className);
            });
            console.log("");
            
            // 尝试Hook找到的类
            console.log("[*] 尝试Hook找到的类...");
            tryHookFoundClasses(foundClasses);
        }
    });
}

// 尝试Hook找到的类
function tryHookFoundClasses(foundClasses) {
    // 尝试Hook OkHttp类
    foundClasses.okhttp.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log("[+] 成功加载类: " + className);
            
            // 检查是否有newCall方法（OkHttpClient的特征）
            if (clazz.newCall) {
                console.log("[!] 发现可能的OkHttpClient类: " + className);
                console.log("    方法: newCall");
            }
            
            // 检查是否有execute方法（Call的特征）
            if (clazz.execute) {
                console.log("[!] 发现可能的Call类: " + className);
                console.log("    方法: execute");
            }
            
            // 检查是否有url方法（Request的特征）
            if (clazz.url) {
                console.log("[!] 发现可能的Request类: " + className);
                console.log("    方法: url");
            }
            
        } catch (e) {
            console.log("[-] 无法加载类 " + className + ": " + e);
        }
    });
    
    // 尝试Hook Retrofit类
    foundClasses.retrofit.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log("[+] 成功加载类: " + className);
            
            // 检查是否有execute方法（OkHttpCall的特征）
            if (clazz.execute) {
                console.log("[!] 发现可能的Retrofit Call类: " + className);
                console.log("    方法: execute");
            }
            
        } catch (e) {
            console.log("[-] 无法加载类 " + className + ": " + e);
        }
    });
    
    // 尝试Hook Okio类
    foundClasses.okio.forEach(function(className) {
        try {
            var clazz = Java.use(className);
            console.log("[+] 成功加载类: " + className);
            
            // 检查是否有write方法（Buffer的特征）
            if (clazz.write) {
                console.log("[!] 发现可能的Buffer类: " + className);
                console.log("    方法: write");
            }
            
            // 检查是否有read方法（Source的特征）
            if (clazz.read) {
                console.log("[!] 发现可能的Source类: " + className);
                console.log("    方法: read");
            }
            
        } catch (e) {
            console.log("[-] 无法加载类 " + className + ": " + e);
        }
    });
}

// 搜索特定方法
function searchMethods() {
    console.log("[*] 搜索网络相关方法...");
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                
                // 获取所有方法
                var methods = clazz.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var methodName = method.getName();
                    
                    // 搜索网络相关方法
                    if (methodName === "newCall" || 
                        methodName === "execute" ||
                        methodName === "getInputStream" ||
                        methodName === "getOutputStream" ||
                        methodName === "connect" ||
                        methodName === "write" ||
                        methodName === "read") {
                        
                        console.log("[!] 发现网络方法: " + className + "." + methodName);
                    }
                }
            } catch (e) {
                // 忽略错误
            }
        },
        onComplete: function() {
            console.log("[+] 方法搜索完成");
        }
    });
}

// 主函数
Java.perform(function() {
    console.log("[+] 混淆类名查找脚本已启动");
    console.log("[*] 开始搜索...");
    
    // 搜索所有类
    searchAllClasses();
    
    // 搜索特定方法
    setTimeout(function() {
        searchMethods();
    }, 2000);
    
    console.log("[*] 搜索可能需要几秒钟时间...");
}); 