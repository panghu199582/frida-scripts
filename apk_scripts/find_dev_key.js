
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动精准 Key 查找模式...");
    console.log("    🎯 目标特征: 以 'DEV' 开头, 长度 39");

    var foundSet = new Set();

    function inspect(str, tag) {
        if (!str) return;
        // 核心过滤逻辑：DEV开头 且 长度39
        if (str.length === 39 && str.indexOf("DEV") === 0) {
            if (!foundSet.has(str)) {
                foundSet.add(str);
                console.log("\n================ [FOUND TARGET KEY] ================");
                console.log("📍 来源: " + tag);
                console.log("🔑 KEY : " + str);
                console.log("==================================================\n");
            }
        }
    }

    // 1. 守株待兔：Hook Mac.init (Key 最终被使用的地方)
    // 这是最精准的，因为它捕捉的是“正在用于加密”的那个 Key
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.init.overload('java.security.Key').implementation = function(key) {
            try {
                var encoded = key.getEncoded();
                if (encoded) {
                    // byte[] -> string (ASCII)
                    var s = "";
                    for(var i=0; i<encoded.length; i++) s += String.fromCharCode(encoded[i]);
                    inspect(s, "HMAC Init (Used)");
                }
            } catch(e) {}
            return this.init(key);
        }
    } catch(e) { 
        console.log("[-] Hook Mac 失败: " + e); 
    }

    // 2. 主动出击：Hook StringBuilder.toString (Key 被组装的地方)
    // 很多时候 Key 是通过 append 拼接出来的，这里能捕捉到“刚出生”的 Key
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function() {
            var s = this.toString(); // 调用原始方法
            inspect(s, "StringBuilder.toString (Created)");
            return s;
        }
    } catch(e) {
        console.log("[-] Hook StringBuilder 失败: " + e);
    }

    // 3. 全局搜索：内存扫描 (即使 App 不动，只要 Key 在内存里就能找到)
    // 这是一个暴露给控制台的函数，需要您手动输入 findKey() 调用
    global.findKey = function() {
        console.log("[*] 正在扫描堆内存中的 String 对象 (可能需要几秒钟)...");
        Java.choose("java.lang.String", {
            onMatch: function(str) {
                inspect(str, "Heap Scan (Memory)");
            },
            onComplete: function() {
                console.log("[*] 内存扫描完成。如果没有输出，说明 Key 暂时不在 String 池中，或者被回收了。");
            }
        });
    }

    console.log("[*] 脚本已就绪。");
    console.log("[*] 👉 方法一: 操作 App 进行 OTP 生成，观察控制台输出。");
    console.log("[*] 👉 方法二: 在 Frida 控制台输入 findKey() 进行全内存扫描。");
});
