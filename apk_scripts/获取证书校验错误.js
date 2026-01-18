Java.perform(function() {
    console.log("[*] 🪤 陷阱已布设：等待 SSLPeerUnverifiedException ...");

    // 1. Hook 异常的构造函数
    var SSLPeerUnverifiedException = Java.use("javax.net.ssl.SSLPeerUnverifiedException");

    SSLPeerUnverifiedException.$init.overload('java.lang.String').implementation = function(message) {
        console.log("\n[!] 🚨 捕获到 SSL 证书校验失败！");
        console.log("    错误信息: " + message);

        // 2. 打印堆栈，寻找凶手
        // 这会告诉我们是哪个类、在哪一行抛出的异常
        var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        
        console.log("    [调用栈/Backtrace]:");
        var lines = stack.split("\n");
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            // 重点关注 o.k0 包下的类
            if (line.indexOf("o.k0.") !== -1) {
                console.log("    👉 " + line.trim());
            }
        }
        
        // 保持异常抛出，让 App 继续走流程（虽然会失败，但我们要的是类名）
        return this.$init(message);
    };
});