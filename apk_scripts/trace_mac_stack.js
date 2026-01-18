
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 追踪 Mac.doFinal 调用栈...");

    var Mac = Java.use("javax.crypto.Mac");
    var Log = Java.use("android.util.Log");
    var Exception = Java.use("java.lang.Exception");

    Mac.doFinal.overload('[B').implementation = function(input) {
        console.log("\n[!] Mac.doFinal 调用!");
        
        // 打印 Input
        var h = "";
        for(var i=0; i<Math.min(input.length, 16); i++) {
             var v = (input[i] & 0xFF).toString(16);
             if(v.length<2) v="0"+v;
             h += v;
        }
        console.log("    Input: " + h);

        // 打印堆栈
        var stack = Log.getStackTraceString(Exception.$new());
        console.log("    Stack:\n" + stack);

        return this.doFinal(input);
    }
});
