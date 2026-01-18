// Get Path of libHappyBus.so
// Usage: frida -U -f com.telkom.mwallet -l get_lib_path.js

Java.perform(function() {
    console.log("[*] 🕵️ Locating libHappyBus.so on disk...");

    var found = false;
    Process.enumerateModules().forEach(function(m) {
        if (m.name.indexOf("HappyBus") !== -1) {
            console.log("\n✅ FOUND MODULE: " + m.name);
            console.log("   ➤ Base Address: " + m.base);
            console.log("   ➤ Size:         " + m.size);
            console.log("   ➤ Path:         " + m.path);
            found = true;
        }
    });

    if (!found) {
        console.log("[-] Module not loaded yet. Trying to force load...");
        try {
             var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
             var x = ExternalFun.$new(); // This forces load
        } catch(e) {}
        
        // Try again
        Process.enumerateModules().forEach(function(m) {
            if (m.name.indexOf("HappyBus") !== -1) {
                console.log("\n✅ FOUND MODULE (After Load): " + m.name);
                console.log("   ➤ Path:         " + m.path);
            }
        });
    }
});
