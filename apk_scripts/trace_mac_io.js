
Java.perform(function() {
    console.log("[*] 🧪 监控 Mac 输入输出 (调试算法细节)...");

    function toHex(b) {
        if (!b) return "null";
        var s = "";
        for(var i=0; i<b.length; i++) { // 不限制长度，我们要看全
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        return s;
    }

    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload('[B').implementation = function(input) {
        var algo = this.getAlgorithm();
        var ret = this.doFinal(input);
        
        // 过滤：只关注输入长度为 8 的 (Time Step)
        if (input.length === 8) {
            console.log("\n-------------------------------------------");
            console.log("⚡️ Algo   : " + algo);
            console.log("📥 Input  : " + toHex(input)); // Time Step
            console.log("📤 Output : " + toHex(ret));   // Raw Hash
            console.log("-------------------------------------------");
        }
        return ret;
    }
});
