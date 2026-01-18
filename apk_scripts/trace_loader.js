// Trace Library Loading and JNI Registration
// Usage: frida -U -f com.telkom.mwallet -l trace_loader.js

Java.perform(function() {
    console.log("[*] 🕵️ Tracing System.loadLibrary and JNI Registration...");

    // 1. Hook System.loadLibrary
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');

    System.loadLibrary.implementation = function(library) {
        console.log("\n📚 System.loadLibrary('" + library + "')");
        // Print stack to see WHO is loading it
        try {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            // Check if it comes from ExternalFun or CoreSec
            if (stack.indexOf("coresec") !== -1 || stack.indexOf("ExternalFun") !== -1) {
                 console.log("   🔥🔥 TARGET IDENTIFIED! This library is loaded by CoreSec!");
            }
        } catch(e) {}
        return this.loadLibrary(library);
    };
    
    // 2. Hook Runtime.loadLibrary0 (Lower level)
    Runtime.loadLibrary0.overload('java.lang.ClassLoader', 'java.lang.String').implementation = function(loader, lib) {
        // console.log("   -> Runtime.loadLibrary0('" + lib + "')");
        return this.loadLibrary0(loader, lib);
    };

    // 3. RegisterNatives Hook (The Holy Grail)
    // This tells us exactly which C function maps to which Java method
    // We hook the native 'RegisterNatives' symbol in libart.so
    
    /* 
       Note: Hooking RegisterNatives via simpler JS Logic:
       We monitor when specific classes are initialized.
    */
    
    var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
    // Trigger class init
    console.log("[*] Forcing ExternalFun class init to trigger loading...");
    try {
        ExternalFun.class.getMethods(); 
    } catch(e) {}

});

// 4. Native Hook for RegisterNatives (Advanced)
// This catches dynamic registration
var RegisterNativesAddr = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("libart.so") !== -1 || m.name.indexOf("libmonosgen.so") !== -1) {
        m.enumerateSymbols().forEach(function(s) {
            if (s.name.indexOf("RegisterNatives") !== -1 && s.name.indexOf("JNI") !== -1 && s.name.indexOf("CheckJNI") === -1) {
                 // console.log("Found RegisterNatives candidate: " + s.name);
                 RegisterNativesAddr = s.address;
            }
        });
    }
});

if (RegisterNativesAddr) {
    Interceptor.attach(RegisterNativesAddr, {
        onEnter: function(args) {
            // args[0] = env
            // args[1] = jclass
            // args[2] = methods
            // args[3] = nMethods
            var env = Java.vm.getEnv();
            var className = env.getClassName(args[1]);
            if (className.indexOf("coresec") !== -1 || className.indexOf("ExternalFun") !== -1) {
                console.log("\n⚡ JNI RegisterNatives called for: " + className);
                var methodCount = args[3].toInt32();
                console.log("   Registering " + methodCount + " methods.");
                
                // Inspect the module calling this
                var returnAddr = this.returnAddress;
                var mod = Process.findModuleByAddress(returnAddr);
                if (mod) {
                    console.log("   🔥🔥 REGISTERED BY MODULE: " + mod.name + " (" + mod.base + ")");
                    console.log("   -> This is your target .so file!");
                }
            }
        }
    });
}
