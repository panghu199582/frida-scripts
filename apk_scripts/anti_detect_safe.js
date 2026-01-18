Java.perform(function() {
    try {
        console.log("[*] Starting safe anti-detection");

        // 只处理关键检测点
        var System = Java.use('java.lang.System');
        
        // 处理环境变量检测
        System.getenv.overload('java.lang.String').implementation = function(name) {
            var result = this.getenv(name);
            if (name === "FRIDA_DNS_SERVER" || name === "FRIDA_INJECT") {
                console.log("[+] Intercepted env check: " + name);
                return null;
            }
            return result;
        };

        // 处理属性检测
        System.getProperty.overload('java.lang.String').implementation = function(name) {
            var result = this.getProperty(name);
            if (name === "frida.server" || name === "frida.client") {
                console.log("[+] Intercepted property check: " + name);
                return null;
            }
            return result;
        };

        // 处理文件检测
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf('/data/local/tmp/frida') !== -1) {
                console.log("[+] Intercepted file check: " + path);
                return false;
            }
            return this.exists();
        };

        console.log("[*] Safe anti-detection installed");
    } catch (e) {
        console.log("[!] Error in safe anti-detection: " + e);
    }
}); 