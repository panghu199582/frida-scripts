// 调用 getKey 并打印返回值
// Usage: frida -H 127.0.0.1:8888 -f com.telkom.mwallet -l call_getkey.js

Java.perform(function() {
    console.log("[*] Waiting for library...");
    
    var intervalId = setInterval(function() {
        var lib = Process.findModuleByName("libHappyBus.so");
        if (lib) {
            clearInterval(intervalId);
            console.log("[+] Library loaded at: " + lib.base);
            
            // Hook encryptRaw 的入口来观察 getKey 的返回值
            // 或者直接尝试调用 getKey
            
            // 方案：Hook encryptRaw，它会调用getKey
            // 我们在getKey返回后立即打印local_98的值
            
            var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
            var inst = null;
            Java.choose("module.libraries.coresec.ExternalFun", {
                onMatch: function(i) { inst = i; },
                onComplete: function() {}
            });
            if (!inst) inst = ExternalFun.$new();
            
            console.log("[*] Calling encryptHmacRaw to trigger getKey...");
            
            var KEY1 = "99bfd9a1a5db9a30eb09d1777f0d273d58123c0fcb18251cdb599d5c218a6e00ebe0113b751364e02915be796918acf4124b896b834cf4fea7251c3d7ef4625bdb7fc42d01c0d17aa26868eac3fdf707aa8a4035fee84115763a6d277e51df74b5885843bd1b2c004c258c49e074914520f5e51db0932131c68465611443002bf907131477312c1de36fd3918be25a0f5a05bb02ad15578c53d657bf5330a3b0752bf1a2668c3a1c9ceb9ec878fa1b445db23679dbed6207a285d14b61e12774099913321f1cba12c09ce968363ed49ef58671da54680805c538068d51efa12f292978779309c3ed1cfe94a15744beba59fa8c7b86c17cd51c54a2e52ecd969a60089bd6b4dccc30dfc8b846633c9798f70d724e10ff227b76b53408b006408c8df923ad5ae1cf2179ea74097267fb4b1f5a3f493d32bcfb038a20905cdd2c455c7477e849d3a8607370df163c4fbfae17961cddc7ffbf843bbe9055ea3960ab2386ee066e694b530ae4604a4bbffb178cd65475df50f733bd2bdacb5d2f65cb";
            
            var result = inst.encryptHmacRaw(
                "1767841753710",
                "c96b489bc518e58c",
                "ff6805b16cbb1911",
                "1767841753710tw4ll3tn30",
                KEY1, KEY1, KEY1,
                "4.43.0"
            );
            
            console.log("\n[+] Result Hash: " + result);
            console.log("[+] Target Hash: 02ac119f104f135dd5c4337f5fbfffee51b431d3e3c8ef79b5e2235ee562762a929d667431b50b5a1cf6bf099b9dcbeced5bef09293a51e5c6395f7d5fcb28f0");
            
            if (result == "02ac119f104f135dd5c4337f5fbfffee51b431d3e3c8ef79b5e2235ee562762a929d667431b50b5a1cf6bf099b9dcbeced5bef09293a51e5c6395f7d5fcb28f0") {
                console.log("\n✅ MATCH! Our inputs are correct.");
            } else {
                console.log("\n❌ Mismatch.");
            }
            
            // 现在尝试Hook getKey的偏移
            // 根据用户提供的偏移 0x1190c9
            var getKeyAddr = lib.base.add(0x1190c9);
            console.log("\n[*] Hooking getKey at: " + getKeyAddr);
            
            Interceptor.attach(getKeyAddr, {
                onLeave: function(retval) {
                    // retval is pointer to std::string
                    // std::string layout: [size/capacity bits] [data ptr or inline data]
                    console.log("\n[getKey Return] Raw retval: " + retval);
                    
                    // Try to read as pointer to string
                    try {
                        var str_ptr = ptr(retval);
                        // First byte contains flags/size for SSO
                        var firstByte = str_ptr.readU8();
                        
                        if ((firstByte & 1) == 0) {
                            // SSO (small string optimization)
                            var size = firstByte >> 1;
                            var data = str_ptr.add(1).readUtf8String(size);
                            console.log("[getKey] Returned (SSO, len=" + size + "): '" + data + "'");
                        } else {
                            // Heap allocated
                            var data_ptr = str_ptr.add(16).readPointer();
                            var size = str_ptr.add(8).readULong();
                            var data = data_ptr.readUtf8String(size);
                            console.log("[getKey] Returned (Heap, len=" + size + "): '" + data + "'");
                        }
                    } catch(e) {
                        console.log("[getKey] Error reading return: " + e);
                    }
                }
            });
            
            // 再次调用以触发Hook
            console.log("\n[*] Calling again to trigger getKey hook...");
            inst.encryptHmacRaw(
                "1767841753710",
                "c96b489bc518e58c",
                "ff6805b16cbb1911",
                "1767841753710tw4ll3tn30",
                KEY1, KEY1, KEY1,
                "4.43.0"
            );
        }
    }, 1000);
});
