/* Frida Script to monitor Native SSL_write 
   保存为: ssl_native_dump.js
*/

function hook_ssl_write() {
    console.log("[*] Starting Native SSL Hooks...");
    if (!Module.findExportByName) {
        Module.findExportByName = function (moduleName, exportName) {
            if (moduleName === null) return Module.findGlobalExportByName(exportName);
            const mod = Process.findModuleByName(moduleName);
            if (mod === null) return null;
            return mod.findExportByName(exportName);
        };
    }

    // Force HTTP/1.1 by filtering ALPN (Removes 'h2')
    function filterALPN(args) {
        try {
            var protos = args[1];
            var len = args[2].toInt32();
            var newProtos = [];
            var p = 0;
            var modified = false;

            while (p < len) {
                var l = protos.add(p).readU8();
                var protocol = protos.add(p + 1).readUtf8String(l);
                
                if (protocol === 'h2') {
                    modified = true;
                } else {
                    newProtos.push(l);
                    for (var i = 0; i < l; i++) {
                        newProtos.push(protos.add(p + 1 + i).readU8());
                    }
                }
                p += 1 + l;
            }

            if (modified) {
                console.log("[!] ALPN: Removing 'h2' to force HTTP/1.1 (Plaintext Headers enabled)");
                var newPtr = Memory.alloc(newProtos.length);
                newPtr.writeByteArray(newProtos);
                args[1] = newPtr;
                // Use NativePointer to be safe
                args[2] = new NativePointer(newProtos.length);
            }
        } catch(e) { console.log("ALPN Filter Error: " + e); }
    }

    // Android 常用的 SSL 库
    var libraries = [
        "libssl.so",
        "libboringssl.so",
        "libconscrypt.so",
        "libmonochrome.so", 
        "stable_cronet_libssl.so"
    ];

    var ssl_write_ptr = null;

    // 遍历查找库中是否存在 SSL_write 导出函数
    for (var i = 0; i < libraries.length; i++) {
        try {
            var lib = libraries[i];
            // 尝试加载库，防止库未加载导致查找失败
            Module.load(lib); 
            
            // Hook ALPN to force HTTP/1.1
            var funcCTX = Module.findExportByName(lib, "SSL_CTX_set_alpn_protos");
            if (funcCTX) {
                Interceptor.attach(funcCTX, { onEnter: function(args) { filterALPN(args); } });
                console.log("[+] Hooked SSL_CTX_set_alpn_protos in " + lib);
            }
            var funcSSL = Module.findExportByName(lib, "SSL_set_alpn_protos");
            if (funcSSL) {
                Interceptor.attach(funcSSL, { onEnter: function(args) { filterALPN(args); } });
                console.log("[+] Hooked SSL_set_alpn_protos in " + lib);
            }

            // 查找 SSL_write 符号
            if (!ssl_write_ptr) {
                ssl_write_ptr = Module.findExportByName(lib, "SSL_write");
                if (ssl_write_ptr) {
                    console.log("[*] Found SSL_write in " + lib + " at " + ssl_write_ptr);
                }
            }
        } catch (e) {
            // ignore
        }
    }

    if (!ssl_write_ptr) {
        console.log("[-] SSL_write not found in common libraries.");
        return;
    }

    // Hook SSL_write(SSL *ssl, const void *buf, int num)
    Interceptor.attach(ssl_write_ptr, {
        onEnter: function (args) {
            // args[0] = ssl context
            // args[1] = buffer (明文数据)
            // args[2] = length
            
            var buf = args[1];
            var len = args[2].toInt32();

            if (len > 0) {
                // 读取内存数据为字符串
                // 只读取前 4KB 或者全部，视情况而定
                var data = buf.readByteArray(len);
                
                // Manually convert to safe string to avoid UTF-8 decoding errors on binary bodies/images
                var safeStr = "";
                var u8 = new Uint8Array(data);
                // Scan first 2048 bytes
                for(var i=0; i<Math.min(u8.length, 2048); i++) {
                    var c = u8[i];
                    if ((c >= 32 && c <= 126) || c == 10 || c == 13) {
                        safeStr += String.fromCharCode(c);
                    } else {
                        safeStr += ".";
                    }
                }
                
                
                    console.log("================ SSL WRITE (Unencrypted) ================");
                    console.log(safeStr); 
                    console.log("=========================================================");
                
            }
        },
        onLeave: function (retval) {
        }
    });
}

setImmediate(hook_ssl_write);