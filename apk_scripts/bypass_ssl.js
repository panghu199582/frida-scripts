/*
 * Android Universal SSL Pinning Bypass (Java + Native)
 * Purpose: Allow traffic interception by proxies like Reqable, Burp, Charles.
 * 
 * Features:
 * 1. Java-level bypass (TrustManager, OkHttp, ConsCrypt).
 * 2. Native-level bypass (OpenSSL, BoringSSL, Cronet).
 * 
 * Usage: frida -U -f com.package.name -l bypass_ssl.js
 */

Java.perform(function() {
    console.log("[.] Android SSL Pinning Bypass / Root Detection Bypass Script Loaded");

    // =============================================================
    // 1. JAVA LAYER BYPASS (TrustManager, OkHttp, etc.)
    // =============================================================
    try {
        var Platform = Java.use("com.android.org.conscrypt.Platform");
        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function(tm, chain, authType, socket) {
            console.log("[+] Bypassing Conscrypt Platform.checkServerTrusted (Socket)");
        };
        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function(tm, chain, authType, engine) {
            console.log("[+] Bypassing Conscrypt Platform.checkServerTrusted (Engine)");
        };
    } catch(e) { /* console.log("[-] Conscrypt not found/hooked"); */ }

    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // Create a custom TrustManager that trusts everything
        var TrustManager = Java.registerClass({
            name: 'com.custom.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        // Hook SSLContext.init to verify our custom TrustManager is used
        var SSLContextInit = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] Intercepted SSLContext.init, replacing TrustManager.");
            SSLContextInit.call(this, keyManager, [TrustManager.$new()], secureRandom);
        };
    } catch(e) { console.log("[-] Java SSLContext Hook failed: " + e); }

    // OkHttp CertificatePinner Bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] Bypassing OkHttp3 CertificatePinner.check for " + hostname);
            return; // Do nothing, effectively bypassing
        };
    } catch(e) { /* console.log("[-] OkHttp3 Pinner not found"); */ }
    
    // OkHttp 4.x / Obfuscated might use slightly different signatures, 
    // but the above usually covers standard implementations.

});

// =============================================================
// 2. NATIVE LAYER BYPASS (BoringSSL, OpenSSL, Cronet)
// =============================================================
// This section targets C/C++ libraries directly.

setTimeout(function() {
    console.log("[.] Starting Native SSL Bypass Hooks...");

    var libNames = [
        "libssl.so", 
        "libboringssl.so", 
        "libconscrypt_jni.so", 
        "libcronet.so",
        "stable_cronet_libssl.so" // Found in your previous logs
    ];

    console.log("[*] Starting Native SSL Hooks...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }

    libNames.forEach(function(lib) {
        var module = Process.findModuleByName(lib);
        if (module) {
            console.log("[+] Hooking SSL functions in " + lib);
            
            // ---------------------------------------------------------
            // A. SSL_set_custom_verify (Common in BoringSSL/Cronet)
            // ---------------------------------------------------------
            // Attempt to disable custom verification callbacks
            var setCustomVerify = Module.findExportByName(lib, "SSL_set_custom_verify");
            if (setCustomVerify) {
                Interceptor.attach(setCustomVerify, {
                    onEnter: function(args) {
                        // args[0] = ssl
                        // args[1] = mode (int)
                        // args[2] = callback
                        console.log("   [+] SSL_set_custom_verify called. Forcing mode=0 (SSL_VERIFY_NONE).");
                        args[1] = ptr(0); // SSL_VERIFY_NONE
                        args[2] = ptr(0); // Null callback
                    }
                });
            }

            // ---------------------------------------------------------
            // B. SSL_get_verify_result (Universal)
            // ---------------------------------------------------------
            // Make the app "think" verification succeeded (X509_V_OK = 0)
            var getVerifyResult = Module.findExportByName(lib, "SSL_get_verify_result");
            if (getVerifyResult) {
                Interceptor.attach(getVerifyResult, {
                    onLeave: function(retval) {
                        // Return 0 (X509_V_OK)
                        if (retval.toInt32() != 0) {
                            // console.log("   [!] SSL_get_verify_result found error, overwriting to 0 (OK).");
                            retval.replace(0);
                        }
                    }
                });
            }

            // ---------------------------------------------------------
            // C. SSL_set_verify (OpenSSL / BoringSSL)
            // ---------------------------------------------------------
            // Force verification mode to NONE (0)
            var setVerify = Module.findExportByName(lib, "SSL_set_verify");
            if (setVerify) {
                Interceptor.attach(setVerify, {
                    onEnter: function(args) {
                        // void SSL_set_verify(SSL *s, int mode, SSL_verify_cb callback);
                        // console.log("   [+] SSL_set_verify called. Setting mode = SSL_VERIFY_NONE (0).");
                        args[1] = ptr(0); 
                        args[2] = ptr(0);
                    }
                });
            }
            
            // ---------------------------------------------------------
            // D. X509_verify_cert (Crypto)
            // ---------------------------------------------------------
            // Often used internally. Return 1 (Success)
            var verifyCert = Module.findExportByName(lib, "X509_verify_cert");
            if (verifyCert) {
                 Interceptor.replace(verifyCert, new NativeCallback(function(ctx) {
                     // console.log("   [+] X509_verify_cert called. Returning 1 (Success).");
                     return 1;
                 }, 'int', ['pointer']));
            }
        }
    });

}, 1000);
