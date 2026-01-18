Java.perform(function() {
    try {
        console.log("[*] Starting enhanced BBL hook");

        // 使用更隐蔽的方式监控网络请求
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            try {
                var url = this.toString();
                if (url.indexOf('bbl') !== -1) {
                    // 使用更隐蔽的方式记录
                    var timestamp = new Date().getTime();
                    console.log("[" + timestamp + "] " + url);
                }
            } catch (e) {
                // 完全忽略错误
            }
            return this.openConnection();
        };

        // 监控请求方法，但更隐蔽
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getRequestMethod.implementation = function() {
            try {
                var method = this.getRequestMethod();
                var url = this.getURL().toString();
                if (url.indexOf('bbl') !== -1) {
                    // 使用更隐蔽的方式记录
                    var timestamp = new Date().getTime();
                    console.log("[" + timestamp + "] " + method);
                }
            } catch (e) {
                // 完全忽略错误
            }
            return this.getRequestMethod();
        };

        // 监控响应，但更隐蔽
        HttpURLConnection.getResponseCode.implementation = function() {
            try {
                var code = this.getResponseCode();
                var url = this.getURL().toString();
                if (url.indexOf('bbl') !== -1) {
                    // 使用更隐蔽的方式记录
                    var timestamp = new Date().getTime();
                    console.log("[" + timestamp + "] " + code);
                }
            } catch (e) {
                // 完全忽略错误
            }
            return this.getResponseCode();
        };

        console.log("[*] Enhanced BBL hook installed");
    } catch (e) {
        // 完全忽略错误
    }
}); 