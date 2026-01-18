
Java.perform(function() {
    console.log("[*] 🕵️‍♀️ 深入挖掘 Mac 实例状态...");

    function inspectObject(obj) {
        try {
            var cls = obj.getClass();
            console.log("    Class: " + cls.getName());
            
            // Try to find "spi" field
            var field = null;
            try {
                field = cls.getDeclaredField("spi");
            } catch(e) {
                // Try parent
                try {
                    field = cls.getSuperclass().getDeclaredField("spi");
                } catch(e2) {}
            }
            
            if (field) {
                field.setAccessible(true);
                var spi = field.get(obj);
                console.log("    SPI Class: " + spi.getClass().getName());
                
                // If it's Android's OpenSSLhmac
                // Inspect fields of SPI
                var fields = spi.getClass().getDeclaredFields();
                for (var i=0; i<fields.length; i++) {
                    fields[i].setAccessible(true);
                    var val = fields[i].get(spi);
                    console.log("      -> " + fields[i].getName() + ": " + val);
                    
                    // Specific check for key byte arrays
                    if (val && val.getClass().isArray() && fields[i].getName().toLowerCase().includes("key")) {
                        console.log("         [POSSIBLE KEY FOUND]: " + JSON.stringify(val));
                    }
                }
            }
        } catch(e) {
            console.log("    Inspect Error: " + e);
        }
    }

    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload('[B').implementation = function(input) {
        console.log("\n[!] Mac.doFinal 捕获! 尝试反射内部...");
        inspectObject(this); // Inspect the current Mac instance
        return this.doFinal(input);
    }
});
