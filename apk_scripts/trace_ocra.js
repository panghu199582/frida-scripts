
Java.perform(function() {
    console.log("🔍 启动 OTP/OCRA 监控脚本...");

    // 1. 监控 Java 层 OCRA 模块
    // 根据之前的分析，包名是 vn.com.pvcombank.RNOcra.OCRAModule
    try {
        var OCRAModule = Java.use("vn.com.pvcombank.RNOcra.OCRAModule");

        // 监控 generateOCRA 方法
        var overloads = OCRAModule.generateOCRA.overloads;
        overloads.forEach(function(overload) {
            overload.implementation = function(ocraSuite, key, counter, question, password, sessionInfo, timeStamp, error) {
                console.log("\n[+] ⚡️ Java OCRA Generate 触发!");
                console.log("    -----------------------------------------");
                console.log("    Arg0 (Suite)    : " + ocraSuite);  // 算法配置，如 OCRA-1:HOTP-SHA256-6:QA08...
                console.log("    Arg1 (Key/Seed) : " + key);        // ⚠️ 重点：密钥
                console.log("    Arg2 (Counter)  : " + counter);
                console.log("    Arg3 (Question) : " + question);   // ⚠️ 重点：这应该就是那个4位 Code
                console.log("    Arg4 (Password) : " + password);   // 可能是 PIN 码
                console.log("    Arg5 (Session)  : " + sessionInfo);
                console.log("    -----------------------------------------");
                
                var ret = this.generateOCRA.apply(this, arguments);
                console.log("    ✅ 生成结果 (OTP) : " + ret);
                return ret;
            };
        });
        console.log("[*] Java OCRA 钩子已安装");
    } catch(e) {
        console.log("[-] Java OCRA Hook 失败 (可能是类名不对): " + e);
    }

    // 2. 监控 Native HMAC (底层算法验证)
    // OCRA 本质上是 HMAC 计算。如果 Java 层参数也是加密的，这里能看到明文。
    try {
        var outputFunc = function(args, ctx) {
            // HMAC(evp_md, key, key_len, d, n, md, md_len)
            var keyAddr = args[1];
            var keyLen = args[2].toInt32();
            var dataAddr = args[3];
            var dataLen = args[4].toInt32();

            // 过滤一下，只看可能是 OTP 相关的（数据较短的情况）
            if (dataLen < 256) { 
                console.log("\n[+] 🔐 Native HMAC 计算 (可能是 OCRA):");
                // 打印 Key
                console.log("    Key (" + keyLen + " bytes):");
                console.log(hexdump(keyAddr, { length: keyLen, ansi: true, header: false }));
                
                // 打印 Data (其中应该包含那个 4位 Code 的 Hex 或者是 Byte 形式)
                console.log("    Data (" + dataLen + " bytes):");
                console.log(hexdump(dataAddr, { length: dataLen, ansi: true, header: false }));
            }
        };

        // 尝试 Hook 系统 SSL 库里的 HMAC
        var libcrypto = Process.findModuleByName("libcrypto.so") || Process.findModuleByName("libboringssl.so");
        if (libcrypto) {
            var hmac = libcrypto.findExportByName("HMAC");
            if (hmac) {
                Interceptor.attach(hmac, {
                    onEnter: function(args) { outputFunc(args, this); }
                });
                console.log("[*] Native HMAC 钩子已安装 (" + libcrypto.name + ")");
            }
        }
    } catch(e) {
        console.log("[-] Native HMAC Hook 失败: " + e);
    }

});
