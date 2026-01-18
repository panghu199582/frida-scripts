Java.perform(function() {
    try {
        console.log("[*] Starting enhanced anti-detection");

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

        // 隐藏 Frida 相关线程
        var Thread = Java.use('java.lang.Thread');
        Thread.start.implementation = function() {
            var name = this.getName();
            if (name.indexOf('frida') !== -1) {
                console.log("[+] Blocked thread: " + name);
                return;
            }
            return this.start();
        };

        // 隐藏 Frida 相关类加载
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function(name, resolve) {
            if (name.indexOf('frida') !== -1) {
                console.log("[+] Blocked class load: " + name);
                return null;
            }
            return this.loadClass(name, resolve);
        };

        // 隐藏 Frida 相关内存映射
        var Memory = Java.use('java.nio.Memory');
        Memory.allocate.overload('int').implementation = function(size) {
            if (size > 1024 * 1024) {  // 如果分配大于1MB的内存
                console.log("[+] Blocked large memory allocation: " + size);
                return null;
            }
            return this.allocate(size);
        };

        console.log("[*] Enhanced anti-detection installed");
    } catch (e) {
        console.log("[!] Error in enhanced anti-detection: " + e);
    }
}); 