try {
        var FOS = Java.use("java.io.FileOutputStream");
        var isSaving = false; // Prevent recursion when WE write the file

        FOS.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            if (!isSaving && len > 5000 && b && b.length >= off+2) {
                 // Check JPEG Magic: 0xFF 0xD8 (Java bytes are signed: -1, -40)
                 if (b[off] == -1 && b[off+1] == -40) { 
                     console.log("\n📸 [Image Trap] JPEG Write Detected (" + len + " bytes)");
                     isSaving = true;
                     try {
                         var path = "/sdcard/Download/img_trap_" + new Date().getTime() + ".jpg";
                         // Use a separate stream to verify we don't trigger our own hook recurisvely 
                         // (though 'isSaving' flag handles it)
                         var f = Java.use("java.io.File").$new(path);
                         var out = FOS.$new(f); 
                         out.write(b, off, len);
                         out.close();
                         console.log("   ✅ Saved Copy to: " + path);
                     } catch(e) { 
                         console.log("   ❌ Trap Save Error: " + e); 
                     }
                     isSaving = false;
                 }
            }
            this.write(b, off, len);
        }
        console.log("✅ Image Trap (FileOutputStream) Active");

    } catch(e) { console.log("Image Trap Error: " + e); }
        