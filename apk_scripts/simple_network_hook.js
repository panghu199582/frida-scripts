/**
 * 简化版Android网络请求监控Hook脚本
 * 快速部署，易于使用
 */

Java.perform(function() {
    console.log("[+] 简化版网络监控Hook已启动");
    
    // 快速配置
    var ENABLE_LOGGING = true;        // 是否启用日志
    var LOG_TO_FILE = false;          // 是否保存到文件
    var LOG_FILE = "/sdcard/network.log"; // 日志文件路径
    
    // 日志函数
    function log(message) {
        if (!ENABLE_LOGGING) return;
        
        var timestamp = new Date().toLocaleString();
        var logMsg = "[" + timestamp + "] " + message;
        console.log(logMsg);
        
        if (LOG_TO_FILE) {
            try {
                var file = new java.io.FileWriter(LOG_FILE, true);
                file.write(logMsg + "\n");
                file.close();
            } catch(e) {
                console.log("[-] 写入文件失败: " + e);
            }
        }
    }
    
    // 1. Hook OkHttp (最常用)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        if (OkHttpClient) {
            OkHttpClient.newCall.implementation = function(request) {
                if (request) {
                    log("=== OkHttp请求 ===");
                    log("URL: " + request.url().toString());
                    log("方法: " + request.method());
                    
                    // 请求头
                    var headers = request.headers();
                    if (headers) {
                        var headerNames = headers.names();
                        for (var i = 0; i < headerNames.size(); i++) {
                            var name = headerNames.get(i);
                            log("请求头: " + name + " = " + headers.get(name));
                        }
                    }
                    
                    // 请求体
                    var body = request.body();
                    if (body) {
                        log("请求体: " + body.toString());
                    }
                    log("================");
                }
                return this.newCall(request);
            };
            log("[+] OkHttp Hook成功");
        }
    } catch(e) {
        log("[-] OkHttp Hook失败: " + e);
    }
    
    // 2. Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        if (HttpURLConnection) {
            HttpURLConnection.setRequestMethod.implementation = function(method) {
                log("[+] HttpURLConnection 方法: " + method);
                return this.setRequestMethod(method);
            };
            
            HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                log("[+] HttpURLConnection 请求头: " + key + " = " + value);
                return this.setRequestProperty(key, value);
            };
            log("[+] HttpURLConnection Hook成功");
        }
    } catch(e) {
        log("[-] HttpURLConnection Hook失败: " + e);
    }
    
    // 3. Hook WebView
    try {
        var WebView = Java.use('android.webkit.WebView');
        if (WebView) {
            WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                log("[+] WebView加载: " + url);
                return this.loadUrl(url);
            };
            log("[+] WebView Hook成功");
        }
    } catch(e) {
        log("[-] WebView Hook失败: " + e);
    }
    
    // 4. Hook Socket连接
    try {
        var Socket = Java.use('java.net.Socket');
        if (Socket) {
            Socket.connect.overload('java.net.SocketAddress').implementation = function(endpoint) {
                log("[+] Socket连接: " + endpoint.toString());
                return this.connect(endpoint);
            };
            log("[+] Socket Hook成功");
        }
    } catch(e) {
        log("[-] Socket Hook失败: " + e);
    }
    
    // 5. Hook SSL/TLS (简化版)
    try {
        var sslWritePtr = Module.findExportByName(null, 'SSL_write');
        if (sslWritePtr) {
            Interceptor.attach(sslWritePtr, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 1000) {
                        log("[+] SSL写入数据长度: " + len);
                    }
                }
            });
        }
        
        var sslReadPtr = Module.findExportByName(null, 'SSL_read');
        if (sslReadPtr) {
            Interceptor.attach(sslReadPtr, {
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 0 && len < 1000) {
                        log("[+] SSL读取数据长度: " + len);
                    }
                }
            });
        }
        log("[+] SSL/TLS Hook成功");
    } catch(e) {
        log("[-] SSL/TLS Hook失败: " + e);
    }
    
    log("[+] 所有Hook设置完成，开始监控...");
});

// 使用说明：
// 1. 将此脚本保存为 simple_network_hook.js
// 2. 使用Frida注入: frida -U -f com.target.app -l simple_network_hook.js
// 3. 或者使用Frida Gadget: 将脚本放入frida-gadget配置中
// 4. 修改上面的配置变量来控制日志输出 