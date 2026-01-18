
Java.perform(function() {
    console.log("======================================================");
    console.log("[*] Enumerating Loaded Modules (.so files)...");
    console.log("======================================================");

    var modules = Process.enumerateModules();
    
    // Interesting keywords to highlight
    var keywords = ["ssl", "crypto", "tls", "http", "curl", "cronet", "okhttp", "boring", "cons", "lnet", "net", "ocbc"];

    modules.forEach(function(mod) {
        var isInteresting = false;
        var lowerName = mod.name.toLowerCase();
        
        // Check if it matches any interesting keyword
        for (var i = 0; i < keywords.length; i++) {
            if (lowerName.includes(keywords[i])) {
                isInteresting = true;
                break;
            }
        }

        if (isInteresting) {
             console.log("🔥 [INTERESTING] " + mod.name + " | Base: " + mod.base + " | Path: " + mod.path);
        } else {
             // Uncomment the line below if you want to see EVERYTHING (spammy)
             // console.log("    " + mod.name + " | Base: " + mod.base);
             
             // Or typically we just want to see the application's own libs (usually in /data/app)
             if (mod.path.includes("/data/app") || mod.path.includes("/data/data")) {
                 console.log("📦 [APP LIB] " + mod.name + " | Base: " + mod.base + " | Path: " + mod.path);
             }
        }
    });

    console.log("======================================================");
    console.log("[*] Enumeration Complete. Total: " + modules.length);
    console.log("======================================================");
    
    // Also try to find specifically if there are hidden ones or common obfuscated ones
    var common = ["libflutter.so", "libapp.so", "libreactnativejni.so", "libmonochrome.so", "libcronet.so"];
    common.forEach(function(n) {
        var m = Process.findModuleByName(n);
        if (m) console.log("✅ Found common framework lib: " + n);
    });
});
