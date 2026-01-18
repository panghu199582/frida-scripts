/*
 * 运行时HTTP库检测脚本
 * 检测应用运行时使用的HTTP请求库
 */

console.log("[+] 运行时HTTP库检测脚本已启动");

Java.perform(function() {
    console.log("[*] 开始检测HTTP库...");
    
    var detectedLibraries = {};
    
    // 1. 检测OkHttp
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            detectedLibraries['OkHttp'] = {
                version: '3.x',
                class: 'okhttp3.OkHttpClient',
                description: 'Square的HTTP客户端库'
            };
            console.log("[+] 检测到 OkHttp 3.x");
        }
    } catch(e) {
        try {
            var OkHttpClient2 = Java.use("com.squareup.okhttp.OkHttpClient");
            if (OkHttpClient2) {
                detectedLibraries['OkHttp'] = {
                    version: '2.x',
                    class: 'com.squareup.okhttp.OkHttpClient',
                    description: 'Square的HTTP客户端库'
                };
                console.log("[+] 检测到 OkHttp 2.x");
            }
        } catch(e2) {
            // OkHttp不存在
        }
    }
    
    // 2. 检测Retrofit
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        if (Retrofit) {
            detectedLibraries['Retrofit'] = {
                version: '2.x',
                class: 'retrofit2.Retrofit',
                description: 'Square的HTTP API客户端库'
            };
            console.log("[+] 检测到 Retrofit 2.x");
        }
    } catch(e) {
        try {
            var Retrofit1 = Java.use("retrofit.Retrofit");
            if (Retrofit1) {
                detectedLibraries['Retrofit'] = {
                    version: '1.x',
                    class: 'retrofit.Retrofit',
                    description: 'Square的HTTP API客户端库'
                };
                console.log("[+] 检测到 Retrofit 1.x");
            }
        } catch(e2) {
            // Retrofit不存在
        }
    }
    
    // 3. 检测Volley
    try {
        var Volley = Java.use("com.android.volley.Volley");
        if (Volley) {
            detectedLibraries['Volley'] = {
                version: '1.x',
                class: 'com.android.volley.Volley',
                description: 'Google的HTTP库'
            };
            console.log("[+] 检测到 Volley");
        }
    } catch(e) {
        // Volley不存在
    }
    
    // 4. 检测Apache HttpClient
    try {
        var HttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        if (HttpClient) {
            detectedLibraries['Apache HttpClient'] = {
                version: '4.x',
                class: 'org.apache.http.impl.client.DefaultHttpClient',
                description: 'Apache的HTTP客户端库'
            };
            console.log("[+] 检测到 Apache HttpClient");
        }
    } catch(e) {
        // Apache HttpClient不存在
    }
    
    // 5. 检测HttpURLConnection (系统自带)
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        if (HttpURLConnection) {
            detectedLibraries['HttpURLConnection'] = {
                version: 'System',
                class: 'java.net.HttpURLConnection',
                description: 'Android系统自带的HTTP连接库'
            };
            console.log("[+] 检测到 HttpURLConnection");
        }
    } catch(e) {
        // HttpURLConnection不存在
    }
    
    // 6. 检测WebView
    try {
        var WebView = Java.use("android.webkit.WebView");
        if (WebView) {
            detectedLibraries['WebView'] = {
                version: 'System',
                class: 'android.webkit.WebView',
                description: 'Android系统WebView组件'
            };
            console.log("[+] 检测到 WebView");
        }
    } catch(e) {
        // WebView不存在
    }
    
    // 7. 检测Socket
    try {
        var Socket = Java.use("java.net.Socket");
        if (Socket) {
            detectedLibraries['Socket'] = {
                version: 'System',
                class: 'java.net.Socket',
                description: 'Java Socket连接'
            };
            console.log("[+] 检测到 Socket");
        }
    } catch(e) {
        // Socket不存在
    }
    
    // 8. 检测自定义网络库
    var customNetworkClasses = [
        "com.acb.mobile.network.NetworkManager",
        "com.acb.mobile.network.ApiService",
        "com.acb.mobile.network.HttpClient",
        "com.acb.mobile.network.RequestHandler",
        "com.acb.mobile.network.ResponseHandler",
        "com.acb.mobile.network.SocketManager",
        "com.acb.mobile.network.SocketClient"
    ];
    
    customNetworkClasses.forEach(function(className) {
        try {
            var cls = Java.use(className);
            if (cls) {
                detectedLibraries['Custom Network'] = {
                    version: 'Custom',
                    class: className,
                    description: '应用自定义网络库'
                };
                console.log("[+] 检测到自定义网络类: " + className);
            }
        } catch(e) {
            // 类不存在
        }
    });
    
    // 9. 检测网络权限
    try {
        var Context = Java.use("android.content.Context");
        var PackageManager = Java.use("android.content.pm.PackageManager");
        
        // 检查网络权限
        var networkPermissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE"
        ];
        
        networkPermissions.forEach(function(permission) {
            try {
                // 这里需要实际的Context对象，暂时跳过
                console.log("[*] 需要检查权限: " + permission);
            } catch(e) {
                // 忽略错误
            }
        });
    } catch(e) {
        // 忽略错误
    }
    
    // 10. 检测活跃的网络连接
    try {
        var NetworkInfo = Java.use("android.net.NetworkInfo");
        if (NetworkInfo) {
            console.log("[+] 检测到网络信息类");
        }
    } catch(e) {
        // 忽略错误
    }
    
    // 打印检测结果
    console.log("\n" + "=" * 50);
    console.log("HTTP库检测结果:");
    console.log("=" * 50);
    
    if (Object.keys(detectedLibraries).length === 0) {
        console.log("未检测到明显的HTTP库");
    } else {
        for (var libName in detectedLibraries) {
            var lib = detectedLibraries[libName];
            console.log(`\n[${libName}]`);
            console.log(`  版本: ${lib.version}`);
            console.log(`  类: ${lib.class}`);
            console.log(`  描述: ${lib.description}`);
        }
    }
    
    // 建议Hook策略
    console.log("\n" + "=" * 50);
    console.log("建议的Hook策略:");
    console.log("=" * 50);
    
    if (detectedLibraries['OkHttp']) {
        console.log("• 使用OkHttp Hook脚本");
        console.log("• Hook okhttp3.OkHttpClient.newCall()");
        console.log("• Hook okhttp3.Response.body()");
        console.log("• Hook okhttp3.Request.url()");
    }
    
    if (detectedLibraries['Retrofit']) {
        console.log("• 使用Retrofit Hook脚本");
        console.log("• Hook retrofit2.Retrofit.create()");
        console.log("• Hook 生成的API接口方法");
    }
    
    if (detectedLibraries['Volley']) {
        console.log("• 使用Volley Hook脚本");
        console.log("• Hook com.android.volley.Request");
        console.log("• Hook com.android.volley.Response");
    }
    
    if (detectedLibraries['HttpURLConnection']) {
        console.log("• 使用HttpURLConnection Hook脚本");
        console.log("• Hook java.net.HttpURLConnection");
        console.log("• Hook java.net.URL.openConnection()");
    }
    
    if (detectedLibraries['Socket']) {
        console.log("• 使用Socket Hook脚本");
        console.log("• Hook java.net.Socket");
        console.log("• Hook SSL/TLS底层函数");
    }
    
    if (detectedLibraries['Custom Network']) {
        console.log("• 使用自定义网络库Hook脚本");
        console.log("• Hook 应用特定的网络类");
        console.log("• Hook 请求和响应处理方法");
    }
    
    console.log("\n[*] 检测完成");
});

// 辅助函数
function log(str) {
    console.log(str);
} 