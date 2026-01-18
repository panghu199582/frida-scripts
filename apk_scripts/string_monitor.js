/*
 * String Monitor - The Blind Eye
 * Hooks StringBuilder to catch OkHttp's toString() output.
 * OkHttp usually constructs logs like "Request{method=...}" or "Response{...}"
 */

Java.perform(function() {
    console.log("[*] 👀 String Monitor Active...");

    var StringBuilder = Java.use("java.lang.StringBuilder");
    
    // Hook append(String)
    StringBuilder.append.overload('java.lang.String').implementation = function(str) {
        if (str) {
            // Heuristics for OkHttp toString() output
            if (str.includes("Request{") || str.includes("Response{") || str.includes("protocol=h2") || str.includes("code=200")) {
                // We need to see the full builder content, not just the chunk
                var fullStr = this.toString();
                if (fullStr.length > 20 && fullStr.length < 5000) { // Filter huge bodies
                     if (fullStr.includes("url=") || fullStr.includes("headers=")) {
                         console.log("\n📜 [TO_STRING CAPTURE]:\n" + fullStr);
                     }
                }
            }
        }
        return this.append(str);
    };
});
