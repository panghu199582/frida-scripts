// Hook Function via Offset (Ghidra Address)
// Usage: Edit OFFSET variable, then run with Frida

// =================CONFIG=================
// TODO: Replace this with the address you see in Ghidra
// Example: var OFFSET = 0x12a200;
var OFFSET = 0x1190c9; 
// ========================================

Java.perform(function() {
    console.log("[*] Waiting for libHappyBus.so...");
    
    // Wait for library load
    var lib = null;
    var interval = setInterval(function() {
        lib = Process.findModuleByName("libHappyBus.so");
        if (lib) {
            clearInterval(interval);
            console.log("[+] Library loaded at: " + lib.base);
            startHook(lib.base);
        } else {
            // Trigger load if needed (optional)
        }
    }, 1000);
    
    function startHook(baseAddr) {
        if (OFFSET === 0x0) {
            console.log("[-] WARNING: You haven't set the OFFSET in the script yet!");
            console.log("    Please open this file and set 'var OFFSET = ...' (from Ghidra).");
            return;
        }

        var targetAddr = baseAddr.add(OFFSET);
        console.log("[*] Hooking Address: " + targetAddr);
        
        Interceptor.attach(targetAddr, {
            onEnter: function(args) {
                console.log("\n[+] Hit Breakpoint at " + targetAddr);
                // Dump arguments?
            },
            onLeave: function(retval) {
                console.log("[+] Return Value: " + retval);
                // Dump memory at retval if it's a pointer
                try {
                    console.log(hexdump(ptr(retval), { length: 32 }));
                } catch(e) {}
            }
        });
    }
});
