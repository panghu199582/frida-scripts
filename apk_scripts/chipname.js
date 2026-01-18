Java.perform(() => {
  const SystemProperties = Java.use('android.os.SystemProperties');
  SystemProperties.get.overload('java.lang.String').implementation = (key) => {
    const blockedProps = [
        "aac_drc_prop", "ab_update_gki_prop", 
        "ro.mediatek.platform", "ro.chipname"
    ];
    
    if (blockedProps.includes(key)) {
        console.log(`[安全绕过] 拦截属性访问: ${key}`);
        return "blocked_by_security";
    }
    return this.get.call(this, key);
    // if (key.includes("mediatek") || key.includes("chipname")) 
    //   return "MT6877";
    // return this.get.call(this, key);
  }
  
  const XposedBridge = Java.use('de.robv.android.xposed.XposedBridge');
  XposedBridge.hookAllMethods(XposedBridge, 'log', {
    before: () => { throw new Error("Disabled"); }
  });

  Interceptor.attach(Module.findExportByName("libtzsmaxk.so", "JNI_OnLoad"), {
    onEnter(args) {
        console.log("[安全绕过] 进入JNI_OnLoad");
        // 计算危险偏移：0x20e8cc + 76 = 0x20e918
        const crashPoint = this.returnAddress.add(0x20e918);
        // 修改内存保护
        Memory.protect(crashPoint, 4, 'rwx');
        // 用NOP指令替换崩溃代码
        crashPoint.writeByteArray([0x1F, 0x20, 0x03, 0xD5]); // ARM64 NOP
    }
  });
});

