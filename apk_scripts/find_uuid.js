
Java.perform(function() {
    console.log("[*] UUID Hunter Started...");
    
    var StringClass = Java.use("java.lang.String");
    var found = false;

    // 1. Monitor HashMap/JSONObject put (To see who sets "clientUUID")
    try {
        var HashMap = Java.use("java.util.HashMap");
        HashMap.put.implementation = function(k, v) {
            if (k && k.toString() === "clientUUID") {
                console.log("\n[!] 🚨 HashMap.put('clientUUID', value) detected!");
                console.log("    Value: " + v);
                console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            }
            return this.put(k, v);
        }
    } catch(e) {}

    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(k, v) {
            if (k === "clientUUID") {
                console.log("\n[!] 🚨 JSONObject.put('clientUUID', value) detected!");
                console.log("    Value: " + v);
                console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            }
            return this.put(k, v);
        }
    } catch(e) {}

    // 2. Monitor SharedPreferences (Persistence)
    try {
        var Activity = Java.use("android.app.Activity");
        var Context = Java.use("android.content.Context");
        // Often UUIDs are stored in SP
        // We catch 'getString' to see if it's read from disk
        // We can't easily hook SharedPreferences interface, but we can hook implementation if we knew it.
        // Instead, let's hook android.app.SharedPreferencesImpl$EditorImpl putString (if accessible) or just Context wrapper?
        // Easier: Hook the method calls in your app code via Stack Trace analysis found in step 1.
    } catch(e) {}
    
    // 3. Monitor Device ID (Common source for persistent IDs)
    try {
        var Secure = Java.use("android.provider.Settings$Secure");
        Secure.getString.implementation = function(resolver, name) {
            var ret = this.getString(resolver, name);
            if (name === "android_id") {
                console.log("[*] Read Android_ID: " + ret);
            }
            return ret;
        }
    } catch(e) {}
    
    // 4. String Constructor Monitor (Aggressive/Noisy)
    // Only enable if you are desperate. It searches for the SPECIFIC UUID value.
    // Replace current target UUID if it changes.
    var TARGET_UUID = "1665464363240-dbb1-7c53-6cfe";
    
    StringClass.$init.overload('[B', 'java.nio.charset.Charset').implementation = function(b, charset) {
        var ret = this.$init(b, charset);
        var s = this.toString();
        if (s.indexOf(TARGET_UUID) !== -1 || s.indexOf("clientUUID") !== -1) {
             console.log("\n[!] String Constructed: " + s);
             console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
        return ret;
    }
    
});
