
Java.perform(function() {
    console.log("[*] 🔍 全局搜索 Key 来源 (DEV...) ...");

    var StringClass = Java.use("java.lang.String");
    
    // 监听 String 构造，看什么时候创建了 DEV... 字符串
    // 这有助于定位从网络流转为 String 的瞬间
    StringClass.$init.overload('[B', 'java.lang.String').implementation = function(bytes, charset) {
        var ret = this.$init(bytes, charset);
        if (ret && ret.indexOf("DEV0000") !== -1) {
            console.log("\n[!] 🚨 发现目标 Key (String byte[] init)!");
            console.log("    Key: " + ret);
            // 打印堆栈看是谁创建的（网络库？JSON解析器？）
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return ret;
    }
    
    // 监听 String(byte[])
    StringClass.$init.overload('[B').implementation = function(bytes) {
        var ret = this.$init(bytes);
        if (ret && ret.indexOf("DEV0000") !== -1) {
            console.log("\n[!] 🚨 发现目标 Key (String byte[] init)!");
            console.log("    Key: " + ret);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return ret;
    }

    // JSON 解析监控
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.getString.implementation = function(key) {
             var ret = this.getString(key);
             if (ret && ret.indexOf("DEV0000") !== -1) {
                 console.log("\n[!] 🚨 发现目标 Key (JSONObject.getString)!");
                 console.log("    Field: " + key);
                 console.log("    Value: " + ret);
                 console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
             }
             return ret;
        }
    } catch(e) {}

    // GSON / Jackson 监控 (如果有)
    // 略，先看上面的 String hook 应该就能抓到 convertStreamToString 的过程
});
