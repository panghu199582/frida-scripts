// trace_detection.js
// This script helps identify what DexProtector is checking during its initialization.

var isChecking = false;

function hook_libc_detection() {
    // Process.getModuleByName("libc.so"); // Not strictly needed unless checking base

    // 1. File Access Monitoring - Use Process.findExportByName
    var openPtr = Process.findExportByName(null, "open");
    var openAtPtr = Process.findExportByName(null, "openat");
    var accessPtr = Process.findExportByName(null, "access");
    var faccessAtPtr = Process.findExportByName(null, "faccessat");
    var fopenPtr = Process.findExportByName(null, "fopen");

    function logFileAccess(path, funcName) {
        if (isChecking) {
            console.log("[Detection Trace] " + funcName + ": " + path);
        }
    }

    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                try {
                    this.path = args[0].readCString();
                    logFileAccess(this.path, "open");
                } catch(e) {}
            }
        });
    }

    if (openAtPtr) {
        Interceptor.attach(openAtPtr, {
            onEnter: function(args) {
                try {
                    // dirfd is args[0], path is args[1]
                    this.path = args[1].readCString();
                    logFileAccess(this.path, "openat");
                } catch(e) {}
            }
        });
    }

    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter: function(args) {
                try {
                    this.path = args[0].readCString();
                    logFileAccess(this.path, "access");
                } catch(e) {}
            }
        });
    }
    
    if (faccessAtPtr) {
        Interceptor.attach(faccessAtPtr, {
            onEnter: function(args) {
                try {
                    this.path = args[1].readCString();
                    logFileAccess(this.path, "faccessat");
                } catch(e) {}
            }
        });
    }

    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            onEnter: function(args) {
                try {
                    this.path = args[0].readCString();
                    logFileAccess(this.path, "fopen");
                } catch(e) {}
            }
        });
    }

    // 2. System Property Monitoring (Detects props like ro.debuggable, ro.kernel.qemu)
    var systemPropertyGetPtr = Process.findExportByName(null, "__system_property_get");
    if (systemPropertyGetPtr) {
        Interceptor.attach(systemPropertyGetPtr, {
            onEnter: function(args) {
                try {
                    this.key = args[0].readCString();
                    if (isChecking) {
                        console.log("[Detection Trace] getprop: " + this.key);
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
               // if (isChecking && this.key) {}
            }
        });
    }
    
    console.log("[*] Anti-detection hooks installed (Passive Mode - Waiting for JNI_OnLoad)");
}

function hook_loader() {
    var dlopen = Process.findExportByName(null, "dlopen");
    var android_dlopen_ext = Process.findExportByName(null, "android_dlopen_ext");

    function hook_jni(name) {
        if (name && name.indexOf("dexprotector") !== -1) {
            console.log("[!] Target Library Loaded: " + name);
            
            var simpleName = name.split("/").pop();
            var mod = Process.findModuleByName(name) || Process.findModuleByName(simpleName);
            
            if (mod) {
                var jniOnLoad = mod.findExportByName("JNI_OnLoad");
                if (jniOnLoad) {
                    console.log("[+] JNI_OnLoad found. Enabling trace...");
                    Interceptor.attach(jniOnLoad, {
                        onEnter: function(args) {
                            console.log(">>> Entering JNI_OnLoad - Detection Trace STARTED <<<");
                            isChecking = true;
                        },
                        onLeave: function(retval) {
                            isChecking = false;
                            console.log("<<< Leavg JNI_OnLoad - Detection Trace STOPPED >>>");
                            console.log("    Return value was: " + retval);
                            
                            // Prevent crash for analysis purposes
                            retval.replace(0x10006); 
                            console.log("    (Patched native return to 0x10006 to keep app alive if possible)");
                        }
                    });
                }
            }
        }
    }

    // Ensure we handle potential errors if these functions are not found (though they should be)
    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function(args) {
                try {
                    this.name = args[0].readCString();
                } catch(e) { this.name = null; }
            },
            onLeave: function(retval) {
                if(this.name) hook_jni(this.name);
            }
        });
    }

    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                try {
                    this.name = args[0].readCString();
                } catch(e) { this.name = null; }
            },
            onLeave: function(retval) {
                if(this.name) hook_jni(this.name);
            }
        });
    }
}

hook_libc_detection();
hook_loader();
