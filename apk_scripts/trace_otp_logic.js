
Java.perform(function() {
    console.log("[*] 🎣 追踪 f.l.a.m.s.b (TOTP Logic)...");

    var SClass = Java.use("f.l.a.m.s");
    
    // b 方法应该接收 Key 和 Time，或者只接收 Time (Key 在内部?)
    // 假设 b 也是 static
    var overloads = SClass.b.overloads;
    overloads.forEach(function(o) {
        o.implementation = function() {
            console.log("\n[+] s.b 被调用!");
            for(var i=0; i<arguments.length; i++) {
                // 如果是 byte[]，打印 Hex
                try {
                    var s = arguments[i].toString();
                    if (s.indexOf("[B") !== -1) {
                         var b = Java.cast(arguments[i], Java.use("[B"));
                         console.log("    Arg" + i + " (Hex): " + toHex(b));
                    } else {
                         console.log("    Arg" + i + ": " + arguments[i]);
                    }
                } catch(e) {
                    console.log("    Arg" + i + ": " + arguments[i]);
                }
            }
            
            var ret = this.b.apply(this, arguments);
            console.log("    Ret: " + ret); // 这里的 Ret 应该是 String (OTP) 或者是 int
            return ret;
        }
    });

    // Helper
    function toHex(b) {
        if (!b) return "null";
        var s = "";
        for(var i=0; i<Math.min(b.length, 32); i++) {
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s+=h;
        }
        return s;
    }
});
