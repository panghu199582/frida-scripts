
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动特定文件读取监控: MY_ALL_EXTERNAL_BANKS");
    var TARGET_FILE = "MY_ALL_EXTERNAL_BANKS";

    // 1. 监控 File 对象构造 (定位文件路径被引用的位置)
    var File = Java.use("java.io.File");
    
    // new File(String path)
    File.$init.overload('java.lang.String').implementation = function(path) {
        if (path && path.indexOf(TARGET_FILE) !== -1) {
            console.log("\n[+] 📄 目标文件对象被创建 (new File(path)): " + path);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.$init(path);
    }
    
    // new File(String parent, String child)
    File.$init.overload('java.lang.String', 'java.lang.String').implementation = function(parent, child) {
        if (child && child.indexOf(TARGET_FILE) !== -1) {
             console.log("\n[+] 📄 目标文件对象被创建 (new File(parent, child)): " + child);
             console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.$init(parent, child);
    }
    
    // new File(File parent, String child)
    File.$init.overload('java.io.File', 'java.lang.String').implementation = function(parent, child) {
        if (child && child.indexOf(TARGET_FILE) !== -1) {
             console.log("\n[+] 📄 目标文件对象被创建 (new File(dir, child)): " + child);
             console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.$init(parent, child);
    }

    // 2. 监控 FileInputStream (定位真正读取文件的时刻)
    var FileInputStream = Java.use("java.io.FileInputStream");
    
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        var path = file.getAbsolutePath();
        if (path.indexOf(TARGET_FILE) !== -1) {
            console.log("\n[+] 📖 开始读取目标文件 (FileInputStream) !");
            console.log("    Path: " + path);
            // 打印堆栈，这通常能直接定位到解密逻辑的上层
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        return this.$init(file);
    }

    console.log("[*] 读取监控已就绪。请重启 App...");
});
