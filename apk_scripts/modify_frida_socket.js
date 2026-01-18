console.log("[*] 开始修改 Frida 的 Unix 抽象套接字名称...");

// 获取当前进程ID
var pid = 8085;
console.log("[+] 当前进程ID: " + pid);

// 修改套接字名称
try {
    // 方法1: 修改内存中的套接字名称
    var socketNamePattern = "/frida-";
    var newSocketName = "/com.android.system-";  // 新套接字名称前缀
    
    // 搜索内存中的套接字名称
    var matches = Memory.scan(Process.enumerateRanges('rw-'), socketNamePattern, {
        onMatch: function(address, size) {
            console.log("[+] 找到套接字名称: " + Memory.readUtf8String(address, size));
            
            // 替换为新名称
            Memory.writeUtf8String(address, newSocketName);
            console.log("[+] 已修改为: " + Memory.readUtf8String(address, size));
        },
        onComplete: function() {
            console.log("[*] 内存扫描完成");
        }
    });
    
    // 方法2: 修改文件系统中的套接字名称
    var socketPath = "/proc/" + pid + "/fd/";
    try {
        var fds = File.list(socketPath);
        for (var i = 0; i < fds.length; i++) {
            var fdPath = socketPath + fds[i];
            var target = File.readLink(fdPath);
            if (target.indexOf("socket") !== -1) {
                console.log("[+] 找到套接字: " + target);
                // 注意: 直接修改文件系统中的套接字名称可能需要root权限
            }
        }
    } catch(e) {
        console.log("[-] 无法读取文件描述符: " + e);
    }
    
    console.log("[*] 套接字名称修改完成");
} catch(e) {
    console.log("[-] 修改套接字名称时出错: " + e);
} 

// 