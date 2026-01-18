
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 被动监控 SharedPreferences 和 s.c (V2)...");

    var TARGET_VAL = "DEV";

    // 1. Hook SharedPreferences.getString
    // 不主动读，而是等 App 自己读的时候截获
    var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferencesImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
        var ret = this.getString(key, defValue);
        if (ret && ret.indexOf(TARGET_VAL) !== -1) {
            console.log("\n[!] 🚨 Found in SharedPreferences!");
            console.log("    Key : " + key);
            console.log("    Val : " + ret);
            console.log("    File: Unknown (Use getAll to find file)");
        }
        return ret;
    };
    
    // 如果是 getAll() 可能会暴露文件名上下文（难）
    
    // 2. Hook s.c 参数
    try {
        var SClass = Java.use("f.l.a.m.s");
        var overloads = SClass.c.overloads;
        overloads.forEach(function(o) {
            o.implementation = function() {
                console.log("\n[+] f.l.a.m.s.c 被调用!");
                for(var i=0; i<arguments.length; i++) {
                    console.log("    Arg" + i + ": " + arguments[i]);
                }
                return this.c.apply(this, arguments);
            }
        });
    } catch(e) {
        console.log("[-] Error hooking c: " + e);
    }
    
    // 3. String 构造监控 (兜底)
    var StringClass = Java.use("java.lang.String");
    StringClass.$init.overload('[B').implementation = function(b) {
        var ret = this.$init(b);
        if (ret.indexOf(TARGET_VAL) !== -1) {
            console.log("[!] String Created with Target Value (from bytes)!");
        }
        return ret;
    }
});
