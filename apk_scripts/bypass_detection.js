Java.perform(function() {
    // --- [PART 1] Anti-Detection Logic ---
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }

    console.log("[*] Anti-Detection: Blocking libalib.so threads...");
    
    var libAlib = null;
    var linkerRequest = Process.findModuleByName("linker64") || Process.findModuleByName("linker");
    
    function isLibAlib(addr) {
        if (!libAlib) libAlib = Process.findModuleByName("libalib.so");
        if (libAlib) {
            var ptrVal = parseInt(addr);
            var base = parseInt(libAlib.base);
            var end = base + libAlib.size;
            return (ptrVal >= base && ptrVal < end);
        }
        return false;
    }

    var pthread_create_ptr = Module.findExportByName(null, "pthread_create");
    if (pthread_create_ptr) {
        Interceptor.replace(pthread_create_ptr, new NativeCallback(function(thread_ptr, attr, start_routine, arg) {
            if (isLibAlib(start_routine)) {
                // console.log("[!] BLOCKED thread creation from libalib.so! Entry: " + start_routine);
                return 0; 
            }
            var original = new NativeFunction(pthread_create_ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            return original(thread_ptr, attr, start_routine, arg);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
    }

    
});
