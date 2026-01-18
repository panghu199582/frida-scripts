Java.perform(function() {
    console.log("[*] 🕵️ Dumping ALL 8 Arguments for encryptHmacRaw");

    var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
    
    // Hook the Sink to dump full keys
    ExternalFun["encryptHmacRaw"].implementation = function(ts, devId, imsi, saltedTs, hex1, hex2, hex3, ver) {
        console.log("\n⚡ [ExternalFun.encryptHmacRaw] CALLED");
        
        console.log("   ➤ Arg[0] Timestamp:      " + ts);
        console.log("   ➤ Arg[1] DeviceId:       " + devId);
        console.log("   ➤ Arg[2] IMSI:           " + imsi);
        console.log("   ➤ Arg[3] Salted TS:      " + saltedTs);
        
        console.log("\n   ➤ Arg[4] KEY 1 (" + (hex1 ? hex1.length : 0) + " chars):");
        console.log(hex1);
        
        console.log("\n   ➤ Arg[5] KEY 2 (" + (hex2 ? hex2.length : 0) + " chars):");
        console.log(hex2);
        
        console.log("\n   ➤ Arg[6] KEY 3 (" + (hex3 ? hex3.length : 0) + " chars):");
        console.log(hex3);
        
        console.log("\n   ➤ Arg[7] AppVersion:     " + ver);
        
        var ret = this.encryptHmacRaw(ts, devId, imsi, saltedTs, hex1, hex2, hex3, ver);
        console.log("\n   🔥 Generated 'raw' Hash: " + ret);
        return ret;
    }
});
