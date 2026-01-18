Java.perform(function() {
    try {
        console.log("[*] Starting anti-detection");

        // 隐藏 Frida 相关特征
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.value;
            if (cmd.indexOf('frida') !== -1 || cmd.indexOf('fs') !== -1) {
                console.log("[+] Blocked process: " + cmd);
                return null;
            }
            return this.start();
        };

        // 隐藏 Frida 相关文件
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf('frida') !== -1 || path.indexOf('fs') !== -1) {
                console.log("[+] Blocked file check: " + path);
                return false;
            }
            return this.exists();
        };

        // 隐藏 Frida 相关端口
        var ServerSocket = Java.use('java.net.ServerSocket');
        ServerSocket.bind.overload('java.net.SocketAddress').implementation = function(endpoint) {
            var port = endpoint.getPort();
            if (port === 27042 || port === 27043) {
                console.log("[+] Blocked port: " + port);
                return;
            }
            return this.bind(endpoint);
        };

        // 隐藏 Frida 相关环境变量
        var System = Java.use('java.lang.System');
        System.getenv.overload('java.lang.String').implementation = function(name) {
            if (name.indexOf('FRIDA') !== -1) {
                console.log("[+] Blocked env: " + name);
                return null;
            }
            return this.getenv(name);
        };

        // 隐藏 Frida 相关属性
        System.getProperty.overload('java.lang.String').implementation = function(name) {
            if (name.indexOf('frida') !== -1) {
                console.log("[+] Blocked property: " + name);
                return null;
            }
            return this.getProperty(name);
        };

        console.log("[*] Anti-detection installed");
    } catch (e) {
        console.log("[!] Error in anti-detection: " + e);
    }
}); 