
console.log("[FRIDA_TEST] Script loaded successfully");
Java.perform(function() {
    console.log("[FRIDA_TEST] Java.perform working");
    try {
        var Log = Java.use("android.util.Log");
        Log.d("FRIDA_TEST", "Log.d from Frida!");
    } catch(e) {
        console.log("[FRIDA_TEST] Log.d failed: " + e);
    }
});
