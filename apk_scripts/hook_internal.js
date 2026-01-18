// 1. Try to find the symbol automatically
// Usage: frida -U -f com.telkom.mwallet -l hook_internal.js

Java.perform(function() {
    console.log("[*] 🔍 Searching for internal symbols in libHappyBus.so...");
    
    var targetName = "getKey"; // Keyword
    var found = false;
    
    var moduleName = "libHappyBus.so";
    var lib = Process.findModuleByName(moduleName);
    
    if (!lib) {
        console.log("[-] Library not loaded. Please triggers hash generation first.");
        return;
    }

    // Enumerate Symbols (not just Exports)
    lib.enumerateSymbols().forEach(function(s) {
        if (s.name.indexOf(targetName) !== -1) {
            console.log("   Found Symbol: " + s.name + " @ " + s.address);
            hookAddress(s.address, s.name);
            found = true;
        }
    });
    
    if (!found) {
        console.log("[-] Symbol not found by name. likely stripped.");
        console.log("    Please obtain the OFFSET from Ghidra and use hook_by_offset.js");
    }
    
    function hookAddress(addr, name) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("\n[+] -> Called " + name);
                // getKey(param_1, param_2, param_3)
                // param_2 is Key1? param_3 is Ver?
                // Print args if needed
            },
            onLeave: function(retval) {
                console.log("[+] <- " + name + " Returns: " + retval);
                // retval might be a pointer to the std::string, or a byte?
                // Let's dump the memory pointed to by retval if it looks like a pointer
                try {
                    var ptr = ptr(retval);
                    console.log("    Dump Ret (Hex): " + hexdump(ptr, { length: 16 }));
                    console.log("    Dump Ret (Str): " + ptr.readUtf8String());
                } catch(e) {}
            }
        });
    }
});
