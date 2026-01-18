
Java.perform(function() {
    console.log("[*] 🎯 锁定 OpenSSLMac SPI 实现 (V3 - Stable)...");

    function toHex(b) {
        if (!b) return "null";
        var s = "";
        for(var i=0; i<Math.min(b.length, 64); i++) {
            var h = (b[i] & 0xFF).toString(16);
            if(h.length<2) h="0"+h;
            s += h;
        }
        return s;
    }

    try {
        var OpenSSLMac = Java.use("com.android.org.conscrypt.OpenSSLMac");
        
        // 只 Hook engineInit，不管 engineUpdate 了
        OpenSSLMac.engineInit.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(key, params) {
            console.log("\n[+] 🔌 OpenSSLMac.engineInit 被调用!");
            
            if (key) {
                // 1. 打印类名 (使用 Frida 属性，不调 Java 方法以防崩)
                console.log("    Key Class Name: " + key.$className);
                
                // 2. 尝试 getEncoded
                try {
                    // 强制转型为 Key 接口
                    var KeyInterface = Java.use("java.security.Key");
                    var castKey = Java.cast(key, KeyInterface);
                    var encoded = castKey.getEncoded();
                    
                    if (encoded) {
                        console.log("    🔥 SECRET KEY (raw bytes): " + toHex(encoded));
                    } else {
                        console.log("    ⚠️ Key.getEncoded() 返回 NULL (可能是 Hardware-backed Key)");
                    }
                } catch(e) {
                    console.log("    [Cast/GetEncoded Error]: " + e);
                }

                // 3. 如果上面失败了，尝试反射打印所有成员变量
                // 这次我们加上父类的字段
                try {
                    var cls = Java.use(key.$className);
                    console.log("    🕵️‍♀️ Inspecting Fields of " + key.$className + "...");
                    
                    // 获取当前类及其父类的所有字段（手动递归太麻烦，我们只看当前类和 Object 之间的那一层）
                    // 简化版：只看当前类的 fields
                    var fields = cls.class.getDeclaredFields();
                    for(var i=0; i<fields.length; i++) {
                        fields[i].setAccessible(true);
                        var name = fields[i].getName();
                        
                        // 尝试获取值 (需要把 key 再次 cast 回具体类，或者 Object)
                        // 这里最稳的是用 Java.cast(key, cls)
                        try {
                            var typedKey = Java.cast(key, cls);
                            var val = fields[i].get(typedKey);
                            
                            // 打印可能的 Key 信息
                            if (val != null) {
                                var valStr = val.toString();
                                // 如果是 byte[]，转 Hex
                                if (valStr.indexOf("[B") !== -1) {
                                    // 这是一个 byte 数组
                                    // 但是在 JS 里没法直接把 Object 变成 byte[] 除非 cast
                                    // 我们仅仅标记它
                                    console.log("      (Byte[]) " + name); 
                                    // 尝试打印
                                    // var bytes = Java.cast(val, Java.use("[B")); // 这样可能会崩
                                } else {
                                    console.log("      " + name + ": " + valStr);
                                }
                            }
                        } catch(getterErr) {}
                    }
                } catch(inspectErr) {
                    console.log("    [Inspection Error]: " + inspectErr);
                }
            }
            
            return this.engineInit(key, params);
        }
        
    } catch(e) {
        console.log("[-] Error hooking OpenSSLMac: " + e);
    }
});
