// 直接 Hook getKey 并打印参数和返回值
// Usage: frida -H 127.0.0.1:8888 -f com.telkom.mwallet -l dump_getkey.js

Java.perform(function() {
    console.log("[*] 等待库加载...");
    
    var checkInterval = setInterval(function() {
        var lib = Process.findModuleByName("libHappyBus.so");
        if (lib) {
            clearInterval(checkInterval);
            console.log("[+] 库已加载: " + lib.base);
            
            // Hook getKey (offset 0x1190c9)
            var getKeyAddr = lib.base.add(0x1190c9);
            console.log("[*] Hook getKey at: " + getKeyAddr);
            
            Interceptor.attach(getKeyAddr, {
                onEnter: function(args) {
                    console.log("\n━━━━━━━ getKey 被调用 ━━━━━━━");
                    // args[0] = return string pointer (std::string*)
                    // args[1] = param_2 (Key1 string)
                    // args[2] = param_3 (Version string)
                    
                    this.retPtr = args[0];
                    
                    // 读取参数
                    try {
                        var key1_ptr = ptr(args[1]);
                        var ver_ptr = ptr(args[2]);
                        
                        // 尝试读取std::string
                        // SSO check
                        var key1_flag = key1_ptr.readU8();
                        var ver_flag = ver_ptr.readU8();
                        
                        var key1_str = "";
                        var ver_str = "";
                        
                        if ((key1_flag & 1) == 0) {
                            // SSO
                            var size = key1_flag >> 1;
                            key1_str = key1_ptr.add(1).readUtf8String(Math.min(size, 100));
                        } else {
                            var data_ptr = key1_ptr.add(16).readPointer();
                            var size = key1_ptr.add(8).readULong();
                            key1_str = data_ptr.readUtf8String(Math.min(size, 100));
                        }
                        
                        if ((ver_flag & 1) == 0) {
                            var size = ver_flag >> 1;
                            ver_str = ver_ptr.add(1).readUtf8String(size);
                        } else {
                            var data_ptr = ver_ptr.add(16).readPointer();
                            var size = ver_ptr.add(8).readULong();
                            ver_str = data_ptr.readUtf8String(size);
                        }
                        
                        console.log("[参数] Key1 (前20字符): " + key1_str.substring(0, 20) + "...");
                        console.log("[参数] Version: " + ver_str);
                    } catch(e) {
                        console.log("[错误] 读取参数失败: " + e);
                    }
                },
                onLeave: function(retval) {
                    console.log("\n[返回] getKey 返完成");
                    
                    // 读取返回的std::string (通过param_1指针)
                    try {
                        var ret_ptr = ptr(this.retPtr);
                        var flag = ret_ptr.readU8();
                        
                        var result_str = "";
                        if ((flag & 1) == 0) {
                            // SSO
                            var size = flag >> 1;
                            result_str = ret_ptr.add(1).readUtf8String(size);
                        } else {
                            var data_ptr = ret_ptr.add(16).readPointer();
                            var size = ret_ptr.add(8).readULong();
                            result_str = data_ptr.readUtf8String(size);
                        }
                        
                        console.log("🔑 getKey 返回值: '" + result_str + "'");
                        console.log("🔑 长度: " + result_str.length);
                        console.log("🔑 Hex: " + toHex(result_str));
                        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                    } catch(e) {
                        console.log("[错误] 读取返回值失败: " + e);
                    }
                }
            });
            
            // Hook 完成后，调用函数
            setTimeout(function() {
                console.log("\n[*] 触发 encryptHmacRaw...");
                var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
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
                
                console.log("[*] 调用完成\n");
            }, 1000);
        }
    }, 500);
    
    function toHex(str) {
        var hex = '';
        for(var i=0; i<str.length; i++) {
            hex += str.charCodeAt(i).toString(16).padStart(2, '0');
        }
        return hex;
    }
});
