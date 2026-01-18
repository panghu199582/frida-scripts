/*
 * DexProtector JNI_OnLoad Hijacker (dlsym approach)
 * 这种方法不依赖 Module.findExportByName，而是利用虚拟机自身的查找机制
 */

function setupBypass() {
    console.log("[*] Setting up dlsym hook to catch JNI_OnLoad...");

    const dlsym = Module.findExportByName(null, "dlsym");
    
    // 用于防止重复 Hook
    let hookedAddresses = new Set();

    Interceptor.attach(dlsym, {
        onEnter: function(args) {
            this.handle = args[0];
            this.symbol = args[1].readCString();
        },
        onLeave: function(retval) {
            if (this.symbol === "JNI_OnLoad") {
                const jniOnLoadAddr = retval;
                
                // 检查是否为空，或者是否已经 Hook 过
                if (jniOnLoadAddr.isNull() || hookedAddresses.has(jniOnLoadAddr.toString())) {
                    return;
                }

                // 获取这属于哪个模块，确认是 DexProtector 的库
                const mod = Process.findModuleByAddress(jniOnLoadAddr);
                if (mod && mod.name.includes("libdexprotector")) {
                    console.log(`[!] ART is looking for JNI_OnLoad in ${mod.name}`);
                    console.log(`[+] Found JNI_OnLoad at ${jniOnLoadAddr}`);
                    
                    hookedAddresses.add(jniOnLoadAddr.toString());

                    // 立即对 JNI_OnLoad 挂钩
                    Interceptor.attach(jniOnLoadAddr, {
                        onEnter: function(args) {
                            console.log(`[-->] Entering JNI_OnLoad (${mod.name})`);
                        },
                        onLeave: function(realRetval) {
                            const retInt = realRetval.toInt32();
                            console.log(`[<--] JNI_OnLoad returned: ${retInt}`);

                            // -401 = JNI_ERR (或者特定错误码)
                            // 0x10006 = JNI_VERSION_1_6 (正常值)
                            if (retInt < 0) {
                                console.log(`[***] DETECTED CRASH ATTEMPT! Patching return value to 0x10006`);
                                realRetval.replace(ptr(0x10006));
                            }
                        }
                    });
                }
            }
        }
    });
}

// 针对 Linker 的部分，确保能在最早时机注入
const linker = Process.getModuleByName(Process.arch === "arm64" ? "linker64" : "linker");
/* 有时候 dlsym hook 可能会漏掉，这里保留一个备用的 dlopen hook
   如果有必要，可以在这里加上，但通常 dlsym 方案最稳。
*/

setupBypass();