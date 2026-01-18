// 🏦 银行 App 专用：Java SSL Unpinning + 流量嗅探
// 启动命令: frida -U -f pgbankApp.pgbank.com.vn -l agent.js

Java.perform(function () {
    console.log("🔥 正在启动银行级抓包脚本...");

    // =============================================================
    // 1. 强力 SSL Unpinning (绕过证书锁定)
    // =============================================================
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl");

    // 针对 Android 7+ 的通用绕过 (Conscrypt)
    try {
        ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            // console.log("🛡️ [Bypass] 绕过 TrustManagerImpl 检查");
            return array_list.$new();
        }
    } catch(e) { console.log("⚠️ TrustManagerImpl Hook 失败 (可能是旧版安卓)"); }

    // 针对标准的 X509TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // 构建一个啥都不检查的 TrustManager
        var TrustManager = Java.registerClass({
            name: 'com.custom.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        // 当 App 尝试初始化 SSL 时，强行塞入我们的 TrustManager
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            // console.log("🛡️ [Bypass] 拦截 SSLContext.init，注入自定义 TrustManager");
            return SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch(e) { console.log("⚠️ SSLContext Hook 失败: " + e); }


    // =============================================================
    // 2. 对抗混淆的日志记录 (不依赖 OkHttp 类名)
    // =============================================================
    
    // 方案 A: Hook java.net.URL (所有网络库的基石)
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function (url) {
            console.log("\n🌐 [URL请求] " + url);
            return this.$init(url);
        };
    } catch(e) {}

    // 方案 B: 强制打开 App 内部的 Log (如果它用了 OkHttp)
    // 我们尝试动态搜索实现了 Interceptor 接口的类，这能绕过混淆
    try {
        // 这一步比较激进，尝试枚举类加载器里的类，寻找 'okhttp3' 字符串
        // 如果 App 混淆得连 okhttp3 包名都改了，这步会失效，但通常包名保留
        var AppClassLoader = Java.use("dalvik.system.PathClassLoader");
        // ... (此处省略复杂的枚举代码，保持脚本轻量，仅依赖上面的 URL Hook 通常足够)
    } catch(e) {}

});