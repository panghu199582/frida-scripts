
Java.perform(function() {
    console.log("[*] 🎣 追踪 f.l.a.m.s.d 方法...");

    try {
        var TargetClass = Java.use("f.l.a.m.s");
        
        // 假设 d 方法签名通过 Mac.doFinal 的返回值推断可能是 byte[] -> String
        // 但安全起见，我们列出所有 overload
        var overloads = TargetClass.d.overloads;
        overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("\n[+] f.l.a.m.s.d 被调用!");
                for(var i=0; i<arguments.length; i++) {
                    console.log("    Arg" + i + ": " + arguments[i]);
                }
                
                var ret = this.d.apply(this, arguments);
                
                console.log("    Ret: " + ret);
                return ret;
            }
        });

    } catch(e) {
        console.log("[-] Class Not Found or Hook Failed: " + e);
        // 如果类名混淆变了，可能需要重新找（但您上面的 stack 是实时的，应该准）
    }
});
