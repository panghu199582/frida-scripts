// Inspect Native Library
// Usage: frida -U -f com.telkom.mwallet -l inspect_native.js

Java.perform(function() {
    console.log("[*] 🔍 Enumerating Modules...");
    
    // 1. Find the library responsible for ExternalFun
    // Usually names like libcoresec.so or similar
    var targetModule = null;
    Process.enumerateModules().forEach(function(m) {
        if (m.path.indexOf("com.telkom.mwallet") !== -1 && m.name.indexOf(".so") !== -1) {
            // Filter system libs
            if (m.name.indexOf("libmonochrome") !== -1 || m.name.indexOf("libwebview") !== -1) return;
            
            console.log("   Found App Module: " + m.name + " (" + m.base + ")");
            
            // Guessing the name based on package 'module.libraries.coresec'
            if (m.name.indexOf("core") !== -1 || m.name.indexOf("sec") !== -1) {
                targetModule = m;
            }
        }
    });

    if (targetModule) {
        console.log("\n[*] 🎯 Targeted Module: " + targetModule.name);
        console.log("[*] Exports:");
        targetModule.enumerateExports().forEach(function(e) {
            console.log("   -> " + e.name + " (" + e.address + ")");
        });

        console.log("\n[*] Imports (looking for crypto):");
        targetModule.enumerateImports().forEach(function(i) {
            if (i.name.toLowerCase().indexOf("hmac") !== -1 || 
                i.name.toLowerCase().indexOf("sha") !== -1 ||
                i.name.toLowerCase().indexOf("crypto") !== -1 ||
                i.name.toLowerCase().indexOf("ssl") !== -1) {
                console.log("   -> " + i.name + " (from " + i.module + ")");
            }
        });
    } else {
        console.log("[-] Could not identify 'coresec' library. Check the list above.");
    }
});
