// 核心逻辑：监听库加载 -> 拦截 JNI_OnLoad -> 篡改返回值
const LIB_NAME_KEYWORD = "libdexprotector"; // 只要包含这个关键字

function hookJNI(moduleName) {
    const module = Process.findModuleByName(moduleName);
    if (!module) return;

    const jniOnLoadAddr = module.findExportByName("JNI_OnLoad");
    if (!jniOnLoadAddr) {
        console.log(`[!] ${moduleName} loaded but JNI_OnLoad not found (stripped?)`);
        return;
    }

    console.log(`[+] Attaching to JNI_OnLoad at ${jniOnLoadAddr} in ${moduleName}`);

    Interceptor.attach(jniOnLoadAddr, {
        onEnter: function(args) {
            console.log(`[*] Entering JNI_OnLoad for ${moduleName}`);
            this.vm = args[0]; // JavaVM*
        },
        onLeave: function(retval) {
            const originalRet = retval.toInt32();
            console.log(`[!] Original JNI_OnLoad return: ${originalRet} (${ptr(originalRet)})`);

            // DexProtector 的特征：如果检测失败，通常返回负值 (如 -401)
            // 或者是其他的错误码。我们强制让它返回 JNI_VERSION_1_6 (0x00010006)
            if (originalRet !== 0x10006) {
                const newRet = 0x10006;
                retval.replace(ptr(newRet));
                console.log(`[+] 💉 PATCHED: JNI_OnLoad return value replaced with ${ptr(newRet)}`);
            }
        }
    });
}

// 监听 dlopen，确保在库加载的第一时间 Hook
const dlopen_names = ["dlopen", "android_dlopen_ext"];
dlopen_names.forEach(func_name => {
    const dlopen_ptr = Process.findExportByName(null, func_name);
    if (dlopen_ptr) {
        Interceptor.attach(dlopen_ptr, {
            onEnter: function(args) {
                this.path = args[0].readCString();
            },
            onLeave: function(retval) {
                if (this.path && this.path.includes(LIB_NAME_KEYWORD)) {
                    const fileName = this.path.split('/').pop();
                    console.log(`[+] Library loaded: ${fileName}`);
                    // 稍微延迟一下确保 Module 列表更新，或者直接在这里 Hook
                    setTimeout(() => {
                        hookJNI(fileName);
                    }, 0);
                }
            }
        });
    }
});

console.log("[*] DexProtector Bypass Script Loaded. Waiting for library...");