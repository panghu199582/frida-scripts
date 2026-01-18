
Java.perform(function() {
    var TARGET = "1665464363240-dbb1-7c53-6cfe";
    console.log("[*] 🎯 Hunting for UUID in JSON: " + TARGET);

    // 1. Hook JSONObject.put (Most likely candidate)
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        
        // Hook put(String name, Object value)
        JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(k, v) {
            if (v && v.toString().indexOf(TARGET) !== -1) {
                console.log("\n[!] 🚨 Found in JSONObject.put!");
                console.log("    Key: " + k);
                console.log("    Value: " + v);
                console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            }
            return this.put(k, v);
        }
    } catch(e) {}

    // 2. Hook LinkedHashMap.put (Used by Gson internally)
    try {
        var HashMap = Java.use("java.util.LinkedHashMap"); // Gson uses LinkedHashMap often
        HashMap.put.implementation = function(k, v) {
            if (v && v.toString().indexOf(TARGET) !== -1) {
                console.log("\n[!] 🚨 Found in LinkedHashMap.put!");
                console.log("    Key: " + k);
                console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            }
            return this.put(k, v);
        }
    } catch(e) {}
    
    // 3. Hook GSON TypeAdapter (If using Gson)
    try {
        // Can be noisy, but effective if we find the write method
        // Just rely on Map/JSON for now to avoid crash.
    } catch(e) {}

    console.log("[*] JSON Trap Set.");
});
