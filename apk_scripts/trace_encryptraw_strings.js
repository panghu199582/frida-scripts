// 打印encryptRaw中使用的派生密钥
// 通过在XOR操作前hook来捕获
// Usage: frida -H 127.0.0.1:8888 -f com.telkom.mwallet -l trace_encryptraw_strings.js

Java.perform(function() {
    console.log("[*] 寻找内部字符串操作...");
    
    // 策略：Hook std::string的操作来捕获中间值
    // 或者直接打印已知有效hash生成时的所有字符串
    
    var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
    
    // 重写encryptHmacRaw来打印所有参数
    ExternalFun.encryptHmacRaw.implementation = function(ts, devid, imsi, salted, key1, key2, key3, ver) {
        console.log("\n━━━━━━━ encryptHmacRaw 调用 ━━━━━━━");
        console.log("TS:      " + ts);
        console.log("DevID:   " + devid);
        console.log("IMSI:    " + imsi);  
        console.log("Salted:  " + salted);
        console.log("Key1 (前30): " + key1.substring(0, 30) + "...");
        console.log("Ver:     " + ver);
        
        console.log("\n[*] 即将调用原始函数...");
        var result = this.encryptHmacRaw(ts, devid, imsi, salted, key1, key2, key3, ver);
        
        console.log("\n[+] Hash 结果: " + result);
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        return result;
    };
    
    // 现在手动测试
    setTimeout(function() {
        console.log("\n[*] 测试调用...");
        var inst = ExternalFun.$new();
        var KEY1 = "99bfd9a1a5db9a30eb09d1777f0d273d58123c0fcb18251cdb599d5c218a6e00ebe0113b751364e02915be796918acf4124b896b834cf4fea7251c3d7ef4625bdb7fc42d01c0d17aa26868eac3fdf707aa8a4035fee84115763a6d277e51df74b5885843bd1b2c004c258c49e074914520f5e51db0932131c68465611443002bf907131477312c1de36fd3918be25a0f5a05bb02ad15578c53d657bf5330a3b0752bf1a2668c3a1c9ceb9ec878fa1b445db23679dbed6207a285d14b61e12774099913321f1cba12c09ce968363ed49ef58671da54680805c538068d51efa12f292978779309c3ed1cfe94a15744beba59fa8c7b86c17cd51c54a2e52ecd969a60089bd6b4dccc30dfc8b846633c9798f70d724e10ff227b76b53408b006408c8df923ad5ae1cf2179ea74097267fb4b1f5a3f493d32bcfb038a20905cdd2c455c7477e849d3a8607370df163c4fbfae17961cddc7ffbf843bbe9055ea3960ab2386ee066e694b530ae4604a4bbffb178cd65475df50f733bd2bdacb5d2f65cb";
        
        inst.encryptHmacRaw(
            "1767841753710",
            "c96b489bc518e58c",
            "ff6805b16cbb1911",
            "1767841753710tw4ll3tn30",
            KEY1, KEY1, KEY1,
            "4.43.0"
        );
    }, 1000);
});
