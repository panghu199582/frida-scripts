console.log("[*] Starting low-level monitoring...");

setTimeout(function() {
    try {
        // 监控系统调用
        Interceptor.attach(Module.findExportByName(null, 'socket'), {
            onEnter: function(args) {
                console.log('[+] Socket created');
            }
        });
        
        Interceptor.attach(Module.findExportByName(null, 'connect'), {
            onEnter: function(args) {
                console.log('[+] Connect called');
            }
        });
        
        console.log("[*] Low-level hooks installed");
    } catch(e) {
        console.log("[!] Error:", e.message);
    }
}, 2000);