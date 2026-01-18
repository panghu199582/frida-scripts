
Java.perform(function() {
    console.log("[*] 🧱 追踪 Key 组装过程 (f.l.a.m.s.c)...");

    try {
        var SClass = Java.use("f.l.a.m.s");
        
        // Hook 'c' 方法 (根据之前的堆栈，b 是被 c 调用的)
        var overloads = SClass.c.overloads;
        overloads.forEach(function(o) {
            o.implementation = function() {
                console.log("\n[+] f.l.a.m.s.c 被调用!");
                for(var i=0; i<arguments.length; i++) {
                    console.log("    Arg" + i + ": " + arguments[i]);
                }
                
                // 打印堆栈，看看是谁调用的 c
                // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));

                var ret = this.c.apply(this, arguments);
                return ret;
            }
        });
        
    } catch(e) {
        console.log("[-] Error hooking c: " + e);
    }
    
    // 顺便搜一下 SharedPreferences，看那个中间值是否存储在本地
    var middleVal = "DEV";
    console.log("[*] 正在检查 SharedPreferences 是否包含: " + middleVal);
    
    Java.use("android.app.ActivityThread").currentApplication().getApplicationContext()
        .getSharedPreferences("verifo", 0) // 常见存储名，可能需要遍历所有 sp
        .getAll().entrySet().toArray().forEach(function(entry){
             if(entry.toString().indexOf(middleVal) !== -1) {
                 console.log("    [FOUND in verifo]: " + entry);
             }
        });

    // 遍历所有 SP 文件的 Helper check
    var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    var rootDir = new java.io.File(context.getFilesDir().getParent() + "/shared_prefs");
    if (rootDir.exists()) {
        var files = rootDir.listFiles();
        if (files) {
            files.forEach(function(f) {
                var fname = f.getName().replace(".xml", "");
                var sp = context.getSharedPreferences(fname, 0);
                var map = sp.getAll();
                var iter = map.keySet().iterator();
                while(iter.hasNext()) {
                    var k = iter.next();
                    var v = map.get(k);
                    if (v && v.toString().indexOf(middleVal) !== -1) {
                        console.log("    [FOUND in SP] File: " + fname + ", Key: " + k + ", Val: " + v);
                    }
                }
            });
        }
    }
});
