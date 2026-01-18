Java.perform(function() {
    try {
        console.log("[*] Starting safe BBL hook");

        // 只监控 URL 和请求方法
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            try {
                var url = this.toString();
                if (url.indexOf('bbl') !== -1) {  // 只记录包含 bbl 的 URL
                    console.log("[+] URL: " + url);
                }
            } catch (e) {
                // 忽略错误
            }
            return this.openConnection();
        };

        // 监控请求方法
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getRequestMethod.implementation = function() {
            try {
                var method = this.getRequestMethod();
                var url = this.getURL().toString();
                if (url.indexOf('bbl') !== -1) {  // 只记录包含 bbl 的 URL
                    console.log("[+] " + method + " " + url);
                }
            } catch (e) {
                // 忽略错误
            }
            return this.getRequestMethod();
        };

        console.log("[*] Safe BBL hook installed");
    } catch (e) {
        // 忽略错误
    }
}); 