/*
 * jshook简单测试脚本
 * 用于验证jshook环境是否正常工作
 */

console.log("[+] jshook测试脚本已启动");

Java.perform(function() {
    console.log("[+] Java.perform执行成功");
    
    // 测试1: 基本类加载
    try {
        var String = Java.use("java.lang.String");
        console.log("[+] 基本类加载测试通过");
    } catch (e) {
        console.log("[-] 基本类加载测试失败: " + e);
    }
    
    // 测试2: HttpURLConnection Hook
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        console.log("[+] HttpURLConnection类加载成功");
        
        // 简单Hook测试
        HttpURLConnection.getURL.implementation = function() {
            var url = this.getURL();
            console.log("[+] 检测到HttpURLConnection.getURL调用: " + url);
            return url;
        };
        
        console.log("[+] HttpURLConnection Hook设置成功");
    } catch (e) {
        console.log("[-] HttpURLConnection测试失败: " + e);
    }
    
    // 测试3: 类枚举（限制数量）
    console.log("[*] 开始类枚举测试（限制100个）...");
    
    var count = 0;
    var maxCount = 100;
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            count++;
            if (count <= 10) {
                console.log("[+] 找到类: " + className);
            }
            if (count >= maxCount) {
                return; // 停止枚举
            }
        },
        onComplete: function() {
            console.log("[+] 类枚举完成，共找到 " + count + " 个类");
        }
    });
    
    console.log("[+] 所有测试完成");
    console.log("[*] 如果看到以上信息，说明jshook环境正常");
}); 