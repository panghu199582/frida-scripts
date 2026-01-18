
Java.perform(function() {
    console.log("[*] 🧵 监控 String 拼接 (寻找 Key 组装)...");

    var StringBuilder = Java.use("java.lang.StringBuilder");
    
    // 监控 toString()
    StringBuilder.toString.implementation = function() {
        var ret = this.toString();
        if (ret && ret.indexOf("DEV00") !== -1 && ret.length > 20) {
            console.log("\n[+] 🧩 StringBuilder.toString() 生成 Key!");
            console.log("    Result: " + ret);
            // 打印这个 Builder 里的内容历史（如果可能的话，但 toString 只通过结果看）
            // 打印堆栈
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return ret;
    }
    
    // 监控 append(String)
    // 看看是谁把中间那段奇怪的 "0707..." append 进去的
    var TARGET_PART = "070722046194072";
    
    StringBuilder.append.overload('java.lang.String').implementation = function(str) {
        if (str && str.indexOf(TARGET_PART) !== -1) {
            console.log("\n[+] 🧩 StringBuilder.append() 插入了目标片段!");
            console.log("    Append: " + str);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.append(str);
    }
});
