Java.perform(function() {
    try {
        // Cronet 引擎构建器
        var CronetEngineBuilder = Java.use("org.chromium.net.CronetEngine$Builder");

        // 强制禁用 HTTP2 和 QUIC
        CronetEngineBuilder.enableHttp2.implementation = function(enable) {
            console.log("[+] Cronet: Force disabling HTTP2");
            return this.enableHttp2(false);
        };

        CronetEngineBuilder.enableQuic.implementation = function(enable) {
            console.log("[+] Cronet: Force disabling QUIC");
            return this.enableQuic(false);
        };
    } catch (e) {
        console.log("[-] Cronet hook failed: " + e);
    }
});