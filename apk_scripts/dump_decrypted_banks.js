
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 启动数据导出脚本 (Dump to /sdcard)...");
    var TARGET_STR = "970448";
    function dumpToFile(dataBytes) {
        try {
            var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var File = Java.use("java.io.File");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            
            // Try internal cache dir first (App always has permission here)
            var dir = context.getCacheDir(); 
            if (!dir) dir = context.getFilesDir();
            
            var f = File.$new(dir, "bank_list_dump.json");
            var path = f.getAbsolutePath();
            
            var fos = FileOutputStream.$new(f);
            fos.write(dataBytes);
            fos.flush();
            fos.close();
            console.log("\n[SUCCESS] ✅ 已将解密数据保存到: " + path);
            console.log("          大小: " + dataBytes.length + " bytes");
            console.log("          (请使用 adb shell su -c 'cat " + path + " > /sdcard/bank_dump_final.json' 导出)");
        } catch(e) {
            console.log("[-] Write failed: " + e);
        }
    }

    // Helper: Decompress GZIP
    function tryGunzip(bytes) {
        try {
            var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
            var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            
            var bis = ByteArrayInputStream.$new(bytes);
            var gzip = GZIPInputStream.$new(bis);
            var bos = ByteArrayOutputStream.$new();
            
            var buffer = Java.array('byte', new Array(1024).fill(0));
            var len;
            while((len = gzip.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch(e) {
            // console.log("Gunzip error: " + e);
            return null;
        }
    }

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        // Hook doFinal
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            if (ret && ret.length > 0) {
                try {
                    var finalData = ret;
                    var isGzip = false;
                    
                    // Check GZIP Magic (1F 8B)
                    if (ret.length > 2 && ret[0] == 31 && ret[1] == -117) { // 31=0x1f, -117=0x8b (signed byte)
                        var gunzipped = tryGunzip(ret);
                        if (gunzipped) {
                             finalData = gunzipped;
                             isGzip = true;
                        }
                    }

                    var s = "";
                    // Check content string
                    for(var i=0; i<Math.min(finalData.length, 1000); i++) s += String.fromCharCode(finalData[i] & 0xff);
                    
                    var hit = false;
                    if (s.toUpperCase().indexOf(TARGET_STR) !== -1) hit = true;

                    if (hit) {
                        console.log("\n[+] 🎯 捕获到目标数据 (" + (isGzip ? "GZIP -> " : "") + "Plain text)!");
                        console.log("    Original Size: " + ret.length);
                        console.log("    Decoded Size : " + finalData.length);
                        console.log("    Preview      : " + s.substring(0, 100).replace(/\n/g, " "));
                        dumpToFile(finalData); // Save the DECODED data
                    }
                } catch(e) {}
            }
            return ret;
        }

    } catch(e) { console.log("[-] Cipher hook error: " + e); }

    console.log("[*] 脚本就绪。请完全重启 App 以触发数据加载。");
});
