// 自动注入脚本
Java.perform(function() {
    // 目标应用包名
    var targetPackage = "com.bbl.mobilebanking";
    
    // 检查当前进程
    var currentPackage = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
    if (currentPackage !== targetPackage) {
        console.log("Not target app, skipping injection");
        return;
    }

    // 加载主脚本
    try {
        // 读取主脚本内容
        var scriptContent = loadScript("bbl_jshook.js");
        if (scriptContent) {
            // 执行主脚本
            eval(scriptContent);
            console.log("Successfully injected main script");
        } else {
            console.log("Failed to load main script");
        }
    } catch(e) {
        console.log("Error during injection: " + e);
    }
});

// 辅助函数：加载脚本文件
function loadScript(scriptName) {
    try {
        var File = Java.use("java.io.File");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var InputStreamReader = Java.use("java.io.InputStreamReader");
        var BufferedReader = Java.use("java.io.BufferedReader");
        var StringBuilder = Java.use("java.lang.StringBuilder");
        
        // 获取脚本路径
        var scriptPath = "/data/local/tmp/" + scriptName;
        var file = File.$new(scriptPath);
        
        if (!file.exists()) {
            console.log("Script file not found: " + scriptPath);
            return null;
        }
        
        // 读取脚本内容
        var fis = FileInputStream.$new(file);
        var isr = InputStreamReader.$new(fis);
        var br = BufferedReader.$new(isr);
        var sb = StringBuilder.$new();
        
        var line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append("\n");
        }
        
        br.close();
        isr.close();
        fis.close();
        
        return sb.toString();
    } catch(e) {
        console.log("Error loading script: " + e);
        return null;
    }
} 