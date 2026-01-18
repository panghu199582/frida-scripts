
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动 'PHUONG DONG' 字符串追踪脚本...");
    var TARGET_STR = "PHUONG DONG";

    // Helper: Check and log
    function check(str, tag) {
        if (str && str.toString().indexOf(TARGET_STR) !== -1) {
            console.log("\n================ [FOUND TARGET STRING] ================");
            console.log("📍 来源: " + tag);
            console.log("📝 内容: " + str);
            console.log("📚 调用栈:");
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            console.log("=======================================================\n");
        }
    }

    // 1. Hook TextView.setText (最直观：看是谁把它显示到界面上的)
    check("Hooking TextView.setText...", "System");
    try {
        var TextView = Java.use("android.widget.TextView");
        TextView.setText.overload('java.lang.CharSequence').implementation = function(text) {
            check(text, "TextView.setText");
            return this.setText(text);
        }
        // Buffer type overload
        TextView.setText.overload('java.lang.CharSequence', 'android.widget.TextView$BufferType').implementation = function(text, type) {
            check(text, "TextView.setText(BufferType)");
            return this.setText(text, type);
        }
    } catch(e) { console.log("[-] TextView hook failed: " + e); }

    // 2. Hook JSON Parsing (通常银行名称来自服务器返回的 JSON)
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.getString.implementation = function(key) {
            var val = this.getString(key);
            check(val, "JSONObject.getString('" + key + "')");
            return val;
        }
    } catch(e) {}
    
    // GSON is also common, but harder to hook generically without exact class name. 
    // Usually tracing String construction covers it.

    // 3. Hook String Construction (StringBuilder)
    // 可能会有点吵，但能抓到拼接过程
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function() {
            var s = this.toString();
            check(s, "StringBuilder.toString");
            return s;
        }
    } catch(e) {}

    // 4. Memory Scan Function
    globalThis.scanMem = function() {
        console.log("[*] 开始内存扫描...");
        Java.choose("java.lang.String", {
            onMatch: function(str) {
                if (str.indexOf(TARGET_STR) !== -1) {
                    console.log("[Mem] Found: " + str);
                }
            },
            onComplete: function() { console.log("[*] 内存扫描完成"); }
        });
    }

    console.log("[*] 脚本已运行。请在 App 中刷新界面，或者输入 scanMem() 进行内存搜索。");
});
