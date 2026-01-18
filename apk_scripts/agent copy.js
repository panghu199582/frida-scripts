Java.perform(function () {
    var KEYWORD = "mobile/v2019/Account/v2/getAccBalanceMethod";      // ⚠️ 只要 URL 包含这个词
    var NEW_HOST = "172.20.6.17:8000";  // ⚠️ 就把它转发到这里

    try {
        var URL = Java.use("java.net.URL");

        // 拦截 new URL(String spec)
        URL.$init.overload('java.lang.String').implementation = function (urlStr) {
            
            if (urlStr.indexOf(KEYWORD) !== -1) {
                console.log("\n[!] 发现特定请求: " + urlStr);
                
                // 执行替换逻辑 (这里仅作示例，简单的把域名替换掉)
                // 假设原 URL 是 https://api.com/v1/special_api
                // 我们把它改成 http://192.168.1.101:8080/v1/special_api
                
                var newUrlStr = urlStr.replace("home.pgbank.com.vn", NEW_HOST);
                // 如果转到本地通常要降级为 http
                newUrlStr = newUrlStr.replace("https://", "http://"); 
                
                console.log("    >>> 🔄 修改为: " + newUrlStr);
                return this.$init(newUrlStr);
            }

            return this.$init(urlStr);
        };
        
        console.log("✅ URL 路径转发已生效");

    } catch (e) {
        console.log("❌ URL Hook 失败 (可能是 App 使用了 OkHttp 直接构建 Request 而非 URL类): " + e);
    }
});