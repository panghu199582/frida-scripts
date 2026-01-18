// jago_bypass.js - Robust Anti-Eversafe for Attach Mode

var SAFETY_ON = true;

function safeFindExport(name) {
    if (!Module.findExportByName) return null;
    var ptr = null;
    try {
        ptr = Module.findExportByName(null, name);
    } catch(e) {}
    
    if (!ptr) {
        // Try locating in specific libc if null
        var libc = Process.findModuleByName("libc.so");
        if (libc) {
             ptr = libc.findExportByName(name);
        }
    }
    // Don't log warnings for dlopen as it's often missing on newer Android
    if (!ptr && name !== "android_dlopen_ext") console.log("⚠️ Warning: Could not find export: " + name);
    return ptr;
}

// 0. Anti-Detect UI Blocker (New)
// Attempt to close/hide the "Detected" dialog if it's an Activity or Dialog
Java.perform(function() {
    console.log("🔥 [UI] Scanning for detection dialogs...");
    
    var Activity = Java.use("android.app.Activity");
    
    // 1. Generic Activity Blocker
    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        var name = this.getClass().getName();
        console.log("Activity created: " + name);
        if (name.toLowerCase().indexOf("detect") >= 0 || name.toLowerCase().indexOf("warning") >= 0 || name.toLowerCase().indexOf("security") >= 0) {
            console.log("🛑 [UI] Blocking Suspicious Activity: " + name);
            this.finish(); // Kill it
            return;
        }
        this.onCreate(bundle);
    };

    // 2. Identify Current Top Context (What is showing NOW?)
    Java.choose("android.app.Activity", {
        onMatch: function(instance) {
             console.log("🔎 [Found Existing Activity] " + instance.getClass().getName());
        },
        onComplete: function() {}
    });

    // 3. Dialog Blocker
    var Dialog = Java.use("android.app.Dialog");
    Dialog.show.implementation = function() {
        console.log("🛑 [UI] Blocking Dialog.show() call!");
        // Print stack trace to see who called show()
        // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        return; 
    };
});

var func_open = safeFindExport("open");
var func_openat = safeFindExport("openat");
var func_dlopen = safeFindExport("android_dlopen_ext");
if (!func_dlopen) func_dlopen = safeFindExport("dlopen"); // Fallback

// --- 1. File System Monitor (Anti-Map Scan) ---
if (func_open) {
    Interceptor.attach(func_open, {
        onEnter: function(args) {
            if (!args[0]) return;
            var path = Memory.readUtf8String(args[0]);
            if (path.indexOf("/proc/") >= 0 && (path.indexOf("maps") >= 0 || path.indexOf("status") >= 0 || path.indexOf("fd") >= 0)) {
                // console.log("[Anti-Detect] Blocking read of: " + path);
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        }
    });
}

if (func_openat) {
    Interceptor.attach(func_openat, {
        onEnter: function(args) {
            if (!args[1]) return;
            var path = Memory.readUtf8String(args[1]);
            if (path.indexOf("/proc/") >= 0 && (path.indexOf("maps") >= 0 || path.indexOf("status") >= 0 || path.indexOf("fd") >= 0)) {
                args[1] = Memory.allocUtf8String("/dev/null");
            }
        }
    });
}

// --- 2. String/Search Blocker (strstr) ---
var func_strstr = safeFindExport("strstr");
if (func_strstr) {
    Interceptor.attach(func_strstr, {
        onEnter: function(args) {
            if (!args[1]) return;
            var needle = "";
            try {
                needle = Memory.readUtf8String(args[1]);
            } catch (e) { return; }
            
            if (needle && (needle.indexOf("frida") >= 0 || needle.indexOf("gum") >= 0 || needle.indexOf("xposed") >= 0)) {
                // console.log("[Anti-Detect] Blocked strstr check for: " + needle);
                args[0] = Memory.allocUtf8String(""); 
            }
        }
    });
}

// --- 3. Ptrace Blocker ---
var func_ptrace = safeFindExport("ptrace");
if (func_ptrace) {
    Interceptor.replace(func_ptrace, new NativeCallback(function(req, pid, addr, data) {
        // console.log("[Anti-Detect] ptrace blocked");
        return 0;
    }, 'int', ['int', 'int', 'pointer', 'pointer']));
}


// --- 4. Library Load Monitor (EverSafe) ---
if (func_dlopen) {
    Interceptor.attach(func_dlopen, {
        onEnter: function(args) {
            if (args[0]) this.path = Memory.readUtf8String(args[0]);
        },
        onLeave: function(retval) {
            if (this.path && (this.path.indexOf("jago") >= 0 || this.path.indexOf("eversafe") >= 0)) {
                console.log("⚠️ [Loader] Loaded suspicious lib: " + this.path);
            }
            // If we are spawning, this is where we would hook JNI_OnLoad
        }
    });
}

// --- 5. Exit/Kill Blocker (Essential for Attach) ---
var func_exit = safeFindExport("exit");
if (func_exit) {
    Interceptor.replace(func_exit, new NativeCallback(function(code) {
        console.log("🛑 [Anti-Kill] exit(" + code + ") BLOCKED. Sleeping thread.");
        Thread.sleep(999999);
    }, 'void', ['int']));
}

var func_kill = safeFindExport("kill");
if (func_kill) {
    Interceptor.replace(func_kill, new NativeCallback(function(pid, sig) {
        console.log("🛑 [Anti-Kill] kill(" + pid + ", " + sig + ") BLOCKED.");
        return 0;
    }, 'int', ['int', 'int']));
}

console.log("✅ [Jago Bypass] Anti-Detection hooks applied (Safe Mode).");

