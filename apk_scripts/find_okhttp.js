/*
 * OkHttp Finder - Frida 17+ Compatible
 * 
 * Purpose: Find the obfuscated OkHttpClient class by signature matching.
 * Principle: OkHttpClient always holds references to specific SSL-related classes.
 */

Java.perform(function() {
    console.log("[*] Scanning for obfuscated OkHttpClient classes...");
    console.log("[*] This may take a minute. Please wait...");

    var targetCandidates = [];

    // Common types inside OkHttpClient
    var SIG_SSL_SOCKET_FACTORY = "javax.net.ssl.SSLSocketFactory";
    var SIG_HOSTNAME_VERIFIER = "javax.net.ssl.HostnameVerifier";
    var SIG_CERTIFICATE_PINNER = "okhttp3.CertificatePinner"; // Might be obfuscated too, so less reliable
    var SIG_PROXY_SELECTOR = "java.net.ProxySelector";
    var SIG_COOKIE_JAR = "okhttp3.CookieJar"; // Obfuscated often

    // Safe class loader
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Filter: Ignore system classes and basic android classes
            if (className.startsWith("java.") || className.startsWith("android.") || className.startsWith("com.android.")) {
                return;
            }

            try {
                var cls = Java.use(className);
                var fields = cls.class.getDeclaredFields();
                
                var hasSSLSocketFactory = false;
                var hasHostnameVerifier = false;
                var hasProxySelector = false;
                var listFieldCount = 0;

                for (var i = 0; i < fields.length; i++) {
                    var field = fields[i];
                    var type = field.getType().getName();

                    if (type === SIG_SSL_SOCKET_FACTORY) hasSSLSocketFactory = true;
                    if (type === SIG_HOSTNAME_VERIFIER) hasHostnameVerifier = true;
                    if (type === SIG_PROXY_SELECTOR) hasProxySelector = true;
                    if (type === "java.util.List") listFieldCount++;
                }

                // OkHttpClient signature: Has SSL context, HostnameVerifier, and usually ProxySelector
                if (hasSSLSocketFactory && hasHostnameVerifier && hasProxySelector) {
                    console.log("\n[+] FOUND CANDIDATE: " + className);
                    console.log("    - Fields found: SSLSocketFactory, HostnameVerifier, ProxySelector");
                    console.log("    - List Fields (protocols/specs?): " + listFieldCount);
                    
                    targetCandidates.push(className);
                    
                    // Further inspection: Try to find the 'protocols' method
                    var methods = cls.class.getDeclaredMethods();
                    for (var j=0; j<methods.length; j++) {
                        var m = methods[j];
                        // protocols() usually returns a List and takes no args (in Client) 
                        // or takes a List and returns Builder (in Builder)
                        var retType = m.getReturnType().getName();
                        var params = m.getParameterTypes();
                        
                        // Check for Builder.protocols(List) -> Builder
                        if (params.length === 1 && params[0].getName() === "java.util.List") {
                            // If return type is the class itself, it's likely a Builder setter
                            if (retType === className) {
                                console.log("    ? Possible Builder Setter: " + m.getName() + "(List) -> " + retType);
                            }
                        }
                    }
                }

            } catch(e) {
                // Ignore loading errors for some classes
            }
        },
        onComplete: function() {
            console.log("\n[*] Scan Complete.");
            if (targetCandidates.length === 0) {
                console.log("[-] No direct matches found. Try searching JADX for 'javax.net.ssl.SSLSocketFactory' usage.");
            } else {
                console.log("[*] Please analyze the candidates above in JADX to confirm which is OkHttpClient.");
            }
        }
    });
});
