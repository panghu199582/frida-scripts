// 终极验证 - Hook encryptRaw 内部的关键点
// Usage: frida -H 127.0.0.1:8888 -f com.telkom.mwallet -l verify_internals.js

Java.perform(function() {
    console.log("[*] 等待库加载...");
    
    var checkInterval = setInterval(function() {
        var lib = Process.findModuleByName("libHappyBus.so");
        if (!lib) return;
        
        clearInterval(checkInterval);
        console.log("[+] 库已加载: " + lib.base);
        
        // Hook ascii2hex (用于查看 shifted 值)
        // ascii2hex 的调用在 encryptRaw Line 133
        // 我们可以 hook 它来看输入
        
        // 或者更简单：直接hook encryptHmacRaw 的 Java 层
        var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
        ExternalFun.encryptHmacRaw.implementation = function(ts, devid, imsi, salted, k1, k2, k3, ver) {
            console.log("\n━━━━━ encryptHmacRaw 调用 ━━━━━");
            console.log("TS:       " + ts);
            console.log("DevID:    " + devid);
            console.log("IMSI:     " + imsi);
            console.log("SaltedTS: " + salted);
            console.log("Version:  " + ver);
            console.log("Key1 (前20): " + k1.substring(0,20) + "...");
            
            var result = this.encryptHmacRaw(ts, devid, imsi, salted, k1, k2, k3, ver);
            
            console.log("\n结果Hash: " + result);
            console.log("━━━━━━━━━━━━━━━━━━━━━\n");
            
            return result;
        };
        
        // 触发调用
        setTimeout(function() {
            var inst = ExternalFun.$new();
            var KEY1 = "99bfd9a1a5db9a30eb09d1777f0d273d58123c0fcb18251cdb599d5c218a6e00ebe0113b751364e02915be796918acf4124b896b834cf4fea7251c3d7ef4625bdb7fc42d01c0d17aa26868eac3fdf707aa8a4035fee84115763a6d277e51df74b5885843bd1b2c004c258c49e074914520f5e51db0932131c68465611443002bf907131477312c1de36fd3918be25a0f5a05bb02ad15578c53d657bf5330a3b0752bf1a2668c3a1c9ceb9ec878fa1b445db23679dbed6207a285d14b61e12774099913321f1cba12c09ce968363ed49ef58671da54680805c538068d51efa12f292978779309c3ed1cfe94a15744beba59fa8c7b86c17cd51c54a2e52ecd969a60089bd6b4dccc30dfc8b846633c9798f70d724e10ff227b76b53408b006408c8df923ad5ae1cf2179ea74097267fb4b1f5a3f493d32bcfb038a20905cdd2c455c7477e849d3a8607370df163c4fbfae17961cddc7ffbf843bbe9055ea3960ab2386ee066e694b530ae4604a4bbffb178cd65475df50f733bd2bdacb5d2f65cb";
            
            console.log("[*] 使用固定时间戳测试...\n");
            var hash = inst.encryptHmacRaw(
                "1767841753710",
                "c96b489bc518e58c",
                "ff6805b16cbb1911",
                "1767841753710tw4ll3tn30",
                KEY1, KEY1, KEY1,
                "4.43.0"
            );
            
            var expected = "02ac119f104f135dd5c4337f5fbfffee51b431d3e3c8ef79b5e2235ee562762a929d667431b50b5a1cf6bf099b9dcbeced5bef09293a51e5c6395f7d5fcb28f0";
            var actual = hash.replace(/,\s*$/, '');  // 去除尾随逗号
            
            console.log("\n[验证] 期望: " + expected);
            console.log("[验证] 实际: " + actual);
            
            if (actual === expected) {
                console.log("\n✅✅✅ 完全匹配！算法验证成功！");
            } else {
                console.log("\n❌ 不匹配");
                console.log("差异: 前10字符 " + actual.substring(0,10) + " vs " + expected.substring(0,10));
            }
        }, 1000);
    }, 500);
});
