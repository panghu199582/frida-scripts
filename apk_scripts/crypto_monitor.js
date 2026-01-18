/*
 * Dedicated Crypto Monitor (SHA-256 & HMAC)
 * Specific Filter: "d4e8eaca052199ccf43a51add80341f6c829b0bdfd6a91f6286d94ff420cf3d6__FCI_EKYC"
 */

Java.perform(function() {
    console.log("[*] Starting Crypto Monitor with Target Filter...");

    var targetString = "d4e8eaca052199ccf43a51add80341f6c829b0bdfd6a91f6286d94ff420cf3d6__FCI_EKYC";
    
    // Global State Map: <hashCode, { algo, key, chunks: [] }>
    var instances = {};

    function getOrInit(instance) {
        var id = instance.hashCode();
        if (!instances[id]) {
            instances[id] = {
                id: id,
                algo: "UNKNOWN",
                key: null,
                chunks: []
            };
            try { instances[id].algo = instance.getAlgorithm(); } catch(e){}
        }
        return instances[id];
    }

    function appendData(instance, data) {
        if (!data) return;
        var info = getOrInit(instance);
        
        // Convert input to simple JS array for storage
        // Handle various input types (byte, byte[], ByteBuffer)
        var arr = [];
        if (data.length !== undefined) { 
             // Byte array
             for(var i=0; i<data.length; i++) arr.push(data[i]);
        } else {
             // Single byte
             arr.push(data);
        }
        info.chunks.push(arr);
    }

    function checkAndLog(instance, result) {
        var id = instance.hashCode();
        var info = instances[id];
        if (!info) return;

        // Reassemble Data
        var totalLen = 0;
        info.chunks.forEach(function(c) { totalLen += c.length; });
        
        var fullBytes = [];
        var fullStr = "";
        
        // Optimize: Check for target string presence efficiently?
        // Since target is ASCII, we can allow loose conversion.
        info.chunks.forEach(function(c) {
            for(var i=0; i<c.length; i++) {
                fullBytes.push(c[i]);
                var val = c[i] & 0xFF;
                if (val >= 32 && val <= 126) fullStr += String.fromCharCode(val);
                else fullStr += ".";
            }
        });

        // FILTER CHECK
        if (fullStr.indexOf(targetString) !== -1) {
             console.log("\n========================================================");
             console.log("🎯 DETECTED TARGET INPUT in " + info.algo + " (ID: " + id + ")");
             console.log("========================================================");
             
             if (info.key) {
                 console.log("🔑 KEY (Hex): " + info.key);
             } else {
                 console.log("🔑 KEY: [None/MessageDigest]");
             }

             console.log("📦 INPUT DATA:");
             console.log("   Total Length: " + totalLen + " bytes");
             // Print formatted version
             console.log("   Full String: " + fullStr);
             
             // Result (Hex)
             var resHex = "";
             if (result) {
                 for(var k=0; k<result.length; k++) {
                     var b = result[k] & 0xFF;
                     if(b<16) resHex += "0";
                     resHex += b.toString(16);
                 }
                 console.log("💎 RESULT (Hex): " + resHex);
             }
             
             console.log("📜 CALL STACK:");
             console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
             console.log("========================================================\n");
        } else {
             // Optional: Log non-matches strictly for debugging if needed?
             // console.log("[Skipped] " + info.algo + " - " + totalLen + " bytes (No Match)");
        }
        
        // Reset specific instance data (Digests reset after use)
        delete instances[id];
    }

    // 1. MessageDigest Hooks
    try {
        var MD = Java.use("java.security.MessageDigest");

        MD.clone.implementation = function() {
            var ret = this.clone();
            var oldId = this.hashCode();
            var newId = ret.hashCode();
            if(instances[oldId]) {
                var newInfo = JSON.parse(JSON.stringify(instances[oldId])); // Deep copy
                newInfo.id = newId;
                instances[newId] = newInfo;
                // console.log("[Clone] " + oldId + " -> " + newId);
            }
            return ret;
        }

        MD.update.overload('byte').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        MD.update.overload('[B').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        MD.update.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            var sub = [];
            for(var i=off; i<off+len; i++) sub.push(b[i]);
            appendData(this, sub);
            this.update(b, off, len);
        }
        MD.update.overload('java.nio.ByteBuffer').implementation = function(buf) {
            // Capture ByteBuffer manually
            if(buf.hasRemaining()) {
                 var arr = [];
                 var dup = buf.duplicate();
                 var limit = Math.min(dup.remaining(), 2048);
                 if (dup.hasArray()) {
                     var start = dup.arrayOffset() + dup.position();
                     var raw = dup.array();
                     for(var i=0; i<limit; i++) arr.push(raw[start+i]);
                 } else {
                     for(var i=0; i<limit; i++) arr.push(dup.get());
                 }
                 appendData(this, arr);
            }
            this.update(buf);
        }

        MD.digest.overload().implementation = function() {
            var ret = this.digest();
            checkAndLog(this, ret);
            return ret;
        }
        MD.digest.overload('[B').implementation = function(b) {
            appendData(this, b);
            var ret = this.digest(b);
            checkAndLog(this, ret);
            return ret;
        }
    } catch(e) { console.log("MD Error: " + e); }

    // 2. Mac (HMAC) Hooks
    try {
        var Mac = Java.use("javax.crypto.Mac");
        
        Mac.init.overload('java.security.Key').implementation = function(key) {
            var info = getOrInit(this);
            try {
                var enc = key.getEncoded();
                if(enc) {
                    var kHex = "";
                    for(var i=0; i<enc.length; i++) {
                        var val = enc[i]&0xFF;
                        if(val<16) kHex += "0";
                        kHex += val.toString(16);
                    }
                    info.key = kHex;
                } else {
                    info.key = "[Key Not Extractable / AndroidKeystore]";
                }
            } catch(e) { info.key = "[Key Error]"; }
            
            // Clear previous data on init
            info.chunks = [];
            this.init(key);
        }

        Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(k, p) {
            getOrInit(this).chunks = [];
            this.init(k, p); // TODO: Capture key here too if needed
        }

        Mac.update.overload('byte').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        Mac.update.overload('[B').implementation = function(b) {
            appendData(this, b);
            this.update(b);
        }
        Mac.update.overload('[B', 'int', 'int').implementation = function(b, off, len) {
            var sub = [];
            for(var i=off; i<off+len; i++) sub.push(b[i]);
            appendData(this, sub);
            this.update(b, off, len);
        }
        Mac.update.overload('java.nio.ByteBuffer').implementation = function(buf) {
             if(buf.hasRemaining()) {
                 var arr = [];
                 var dup = buf.duplicate();
                 var limit = Math.min(dup.remaining(), 2048);
                 if (dup.hasArray()) {
                     var start = dup.arrayOffset() + dup.position();
                     var raw = dup.array();
                     for(var i=0; i<limit; i++) arr.push(raw[start+i]);
                 } else {
                     for(var i=0; i<limit; i++) arr.push(dup.get());
                 }
                 appendData(this, arr);
            }
            this.update(buf);
        }

        Mac.doFinal.overload().implementation = function() {
            var ret = this.doFinal();
            checkAndLog(this, ret);
            return ret;
        }
        Mac.doFinal.overload('[B').implementation = function(b) {
            appendData(this, b);
            var ret = this.doFinal(b);
            checkAndLog(this, ret);
            return ret;
        }

    } catch(e) { console.log("Mac Error: " + e); }

});
