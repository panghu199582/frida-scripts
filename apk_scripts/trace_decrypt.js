Java.perform(function() {
    console.log("[*] Starting Full Tracing (Native + Java)...");

    var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
    var TaskCrypto = Java.use("module.libraries.coresec.implement.TaskCrypto");

    // 1. Hook ALL Native Methods (Safe List)
    var nativeMethods = [
        "encryptJson",
        "decryptJson",
        "encryptHmacRaw",
        "encryptHmacWar",
        "encryptPlainText",
        "generateQr",
        "preferenceKey", // Skip (Unstable)
        "preferenceValueEncrypt", // Skip
    ];

    nativeMethods.forEach(function(mName) {
        if (ExternalFun[mName]) {
            var overloads = ExternalFun[mName].overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("\n[NATIVE] " + mName + " called");
                    
                    // Capture args
                    for(var i=0; i<arguments.length; i++) {
                        var arg = arguments[i];
                        if (arg && arg.toString().length > 100) {
                             arg = arg.toString();
                        }
                        console.log("    Arg[" + i + "]: " + arg);
                    }
                    
                    var ret = this[mName].apply(this, arguments);
                    
                    // Cleanup return logging
                    var retStr = ret;
                    if (retStr && retStr.toString().length > 100) {
                         retStr = retStr.toString();
                    }
                    console.log("    Return: " + retStr);
                    if (mName === "preferenceValueEncrypt" && arguments[0].includes("TCASH|")) {
                        console.log("[*] preferenceValueEncrypt called");
                        console.log("    Arg[0]: " + ret.toString());
                        
                    }
                    return ret;
                }
            });
        }
    });

    

    // 3. Keep Java Context
    TaskCrypto.generateBody1.overload('java.lang.String', 'java.lang.String').implementation = function(a, b) {
        console.log("\n[!] TaskCrypto.generateBody1 called");
        return this.generateBody1(a, b);
    }

});
