Java.perform(function () {
    console.log("[*] 脚本已加载，请按【音量+】键触发复制...");

    var StringClass = Java.use("java.lang.String");
    var Toast = Java.use("android.widget.Toast");
    var ClipboardManager = Java.use("android.content.ClipboardManager");
    var ClipData = Java.use("android.content.ClipData");
    var Activity = Java.use("android.app.Activity");

    function copyToken(context) {
        try {
            // 获取剪贴板服务
            var cmService = context.getSystemService("clipboard");
            if (!cmService) {
                console.log("[-] 无法获取剪贴板服务");
                return;
            }
            var cm = Java.cast(cmService, ClipboardManager);
            
            // --- 模拟获取 Token ---
            var jsToken = "Token_" + new Date().getTime(); 

            // 【关键修复点】：显式创建 Java 字符串对象
            // 这样 Frida 就不会搞错类型了
            var labelJava = StringClass.$new("Frida");
            var textJava = StringClass.$new(jsToken);

            // 调用 newPlainText，传入标准的 Java 对象
            var clip = ClipData.newPlainText(labelJava, textJava);
            cm.setPrimaryClip(clip);

            console.log("[+] Token 已复制: " + jsToken);
            
            // 弹窗提示
            Java.scheduleOnMainThread(function() {
                try {
                    // Toast 的文本也必须是 Java 字符串
                    var msg = StringClass.$new("复制成功: " + jsToken);
                    Toast.makeText(context, msg, 1).show();
                } catch(e) {
                    console.log("[-] Toast 失败: " + e);
                }
            });

        } catch (e) {
            console.log("[-] 业务逻辑出错: " + e);
            // 打印详细报错堆栈，方便排查
            console.log(Java.use("android.util.Log").getStackTraceString(e));
        }
    }

    // Hook 按键事件
    Activity.dispatchKeyEvent.implementation = function (event) {
        var action = event.getAction();
        var code = event.getKeyCode();
        
        // 0 = Down (按下)
        if (action === 0) {
            if (code === 24) { // 音量上键 (Volume Up)
                console.log("[*] 音量+ 按下 -> 执行 Copy");
                copyToken(this); 
                return true; // 拦截按键，不调节音量
            }
            if (code === 25) { // 音量下键
                console.log("[*] 音量- 按下 (未定义功能)");
                return true; 
            }
        }
        return this.dispatchKeyEvent(event);
    };
});