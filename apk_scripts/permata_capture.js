
/*
 * PermataMobileX Network Capture & Pinning Bypass
 * Target: net.myinfosys.PermataMobileX
 */

Java.perform(function() {
    console.log("[*] 🚀 Starting PermataMobileX Hooking...");

    // ====================================================================
    // 1. SSL PINNING BYPASS (Universal)
    // ====================================================================
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            // console.log("[+] Bypassing SSL Pinning (TrustManagerImpl)");
            return array_list.$new();
        }

        // Hook HttpsURLConnection (older stack)
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            // console.log("[+] HttpsURLConnection HostnameVerifier set to NULL");
            return null;
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
            // console.log("[+] HttpsURLConnection SSLSocketFactory set to NULL");
            return null;
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            // console.log("[+] Bypassing HostnameVerifier");
            return null;
        };

    } catch(e) { console.log("[-] SSL Bypass Error (Non-Fatal): " + e); }

    // ====================================================================
    // 2. OKHTTP3 LOGGING (High Level)
    // ====================================================================
    try {
        // Try to find OkHttp classes automatically or use standard names
        var RealCall = Java.use("okhttp3.RealCall");
        
        RealCall.execute.overload().implementation = function() {
            var req = this.request();
            console.log("\n📦 [OkHttp-Sync] " + req.method() + " " + req.url());
            return this.execute();
        }

        RealCall.enqueue.overload('okhttp3.Callback').implementation = function(cb) {
            var req = this.request();
            console.log("\n📦 [OkHttp-Async] " + req.method() + " " + req.url());
            
            // Optional: Wrap callback to log response (omitted for stability for now)
            return this.enqueue(cb);
        }
        console.log("[+] OkHttp3 Hooks Installed");

    } catch(e) {
        console.log("[-] OkHttp3 standard hooks failed. App might be obfuscated.");
    }

    // ====================================================================
    // 3. NATIVE SSL LOGGING (Low Level Fallback)
    // ====================================================================
    setTimeout(function() {
        var funcs = ["SSL_write", "SSL_read"];
        var libs = ["libssl.so", "libboringssl.so", "libconscrypt.so"];
        
        libs.forEach(function(lib) {
            var m = Process.findModuleByName(lib);
            if (m) {
                console.log("[+] Found Native SSL Lib: " + lib);
                funcs.forEach(function(fname) {
                    var ptr = Module.findExportByName(lib, fname);
                    if (ptr) {
                        Interceptor.attach(ptr, {
                            onEnter: function(args) {
                                if (fname === "SSL_write") {
                                    var len = args[2].toInt32();
                                    if (len > 0) {
                                        try {
                                            var buf = args[1].readByteArray(Math.min(len, 2048));
                                            var u8 = new Uint8Array(buf);
                                            var str = "";
                                            for(var i=0;i<u8.length;i++) {
                                                var c=u8[i];
                                                if((c>=32&&c<=126)||c==10||c==13) str+=String.fromCharCode(c); else str+=".";
                                            }
                                            if (str.match(/^(GET|POST|PUT|DELETE|HTTP\/)/)) {
                                                console.log("\n🔐 ["+lib+"::"+fname+"]\n" + str);
                                            }
                                        } catch(e){}
                                    }
                                } else {
                                    this.buf = args[1];
                                }
                            },
                            onLeave: function(retval) {
                                if (fname === "SSL_read" && this.buf) {
                                    var len = retval.toInt32();
                                    if (len > 0) {
                                         // Log response...
                                    }
                                }
                            }
                        });
                    }
                });
            }
        });
    }, 1000);

});
