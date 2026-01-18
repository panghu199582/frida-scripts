/*
 * Pgbank Capture Script
 * Focus: Only capturing critical info (CaptureInfo) triggers
 * Features:
 * 1. Capture JSON body params (clientDeviceID, devicePubKey, TMK, etc.) from AES Cipher
 * 2. Capture OTP Secret Key from Mac/StringBuilder
 * 3. Volume Key to Copy CaptureInfo
 */

console.log("[*] Initializing Pgbank Capture Script...");

var CaptureInfo = {
    "clientDeviceID": "",
    "devicePubKey": "",
    "deviceId": "",
    "TMK": "",
    "userID": "",
    "phone_no": "",
    "otpSecretKey": "",
    "appName": "MOBILE",
    "deviceName": "Pixel 6a",
    "version": "3.2.9",
    "aesIV": "7f1b041c7586c6ba094c913725eeb039" // Static from pgb_source.js
};

Java.perform(function() {
    var StringClass = Java.use("java.lang.String");
    var ClipboardManager = Java.use("android.content.ClipboardManager");
    var ClipData = Java.use("android.content.ClipData");
    var Toast = Java.use("android.widget.Toast");
    var Activity = Java.use("android.app.Activity");

    // ================== UTILS ==================
    function byteArrayToString(bytes) {
        if (!bytes) return "null";
        try {
            var str = StringClass.$new(bytes, "UTF-8");
            // Check if it looks printable
            var readable = 0;
            var len = Math.min(str.length(), 100);
            for(var i=0; i<len; i++) {
                var c = str.charCodeAt(i);
                if ((c >= 32 && c <= 126) || c == 10 || c == 13) readable++;
            }
            if (len > 0 && readable / len > 0.8) return str.toString();
        } catch(e) {}
        return null;
    }

    // ================== KEY CAPTURE (OTP Secret) ==================
    var foundKeySet = new Set();
    function inspectKey(str, tag) {
        if (!str) return;
        // Logic: Starts with DEV and length is 39
        if (str.length === 39 && str.indexOf("DEV") === 0) {
            if (!foundKeySet.has(str)) {
                foundKeySet.add(str);
                console.log("\n[+] 🔑 Found OTP Secret Key (" + tag + "): " + str);
                CaptureInfo['otpSecretKey'] = str;
            }
        }
    }

    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function() {
            var s = this.toString();
            inspectKey(s, "StringBuilder");
            return s;
        }
    } catch(e) {}

    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.init.overload('java.security.Key').implementation = function(key) {
            try {
                var encoded = key.getEncoded();
                if (encoded) {
                    var s = "";
                    for(var i=0; i<encoded.length; i++) s += String.fromCharCode(encoded[i]);
                    inspectKey(s, "HMAC.init");
                }
            } catch(e) {}
            return this.init(key);
        }
    } catch(e) {}

    // ================== BODY CAPTURE (AES Cipher) ==================
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var cipherMap = new Map();

        var initImpl = function(instance, mode, key, spec, random) {
            var algo = instance.getAlgorithm();
            // We only care about AES ENCRYPT (mode 1)
            if (algo.toUpperCase().includes("AES") && mode === 1) {
                cipherMap.set(instance.hashCode(), { algo: algo, mode: mode });
            }
        };

        // Hook Init overloads
        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            this.init(mode, key);
            initImpl(this, mode, key, null, null);
        };
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, spec) {
            this.init(mode, key, spec);
            initImpl(this, mode, key, spec, null);
        };
        Cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function(mode, key, random) {
            this.init(mode, key, random);
            initImpl(this, mode, key, null, random);
        };

        // Hook DoFinal
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var ret = this.doFinal(input);
            try {
                var ctx = cipherMap.get(this.hashCode());
                if (ctx && ctx.algo.toUpperCase().includes("AES") && ctx.mode === 1) {
                    // This is an AES Encryption
                    // Try to parse input as string -> JSON
                    var inputStr = byteArrayToString(input);
                    if (inputStr) {
                         // Simple check if it looks like JSON
                         if (inputStr.trim().startsWith("{")) {
                             try {
                                 var jsonSave = JSON.parse(inputStr);
                                 var updated = false;
                                 
                                 if (jsonSave['clientDeviceID']) { CaptureInfo['clientDeviceID'] = jsonSave['clientDeviceID']; updated = true; }
                                 if (jsonSave['devicePubKey']) { CaptureInfo['devicePubKey'] = jsonSave['devicePubKey']; updated = true; }
                                 if (jsonSave['deviceId']) { CaptureInfo['deviceId'] = jsonSave['deviceId']; updated = true; }
                                 if (jsonSave['TMK']) { CaptureInfo['TMK'] = jsonSave['TMK']; updated = true; }
                                 if (jsonSave['userID']) { CaptureInfo['userID'] = jsonSave['userID']; updated = true; }
                                 if (jsonSave['phone_no']) { CaptureInfo['phone_no'] = jsonSave['phone_no']; updated = true; }
                                 
                                 // Update derived fields
                                 if(CaptureInfo['clientDeviceID']) CaptureInfo['UniqueDeviceId'] = CaptureInfo['clientDeviceID'];

                                 if (updated) {
                                     console.log("\n[+] 📦 Captured Body Params from AES:");
                                     console.log(JSON.stringify(CaptureInfo, null, 2));
                                 }
                             } catch(e) {
                                 // Not valid JSON, ignore
                             }
                         }
                    }
                }
            } catch(e) {}
            return ret;
        };

    } catch(e) { console.log("Cipher Hook Error: " + e); }

    // ================== VOLUME KEY LISTENER ==================
    try {
        Activity.dispatchKeyEvent.implementation = function(event) {
            if (event.getAction() === 0 && event.getKeyCode() === 24) { // Volume Up
                try {
                    var context = this;
                    
                    // Final Touchups before copy
                    if(CaptureInfo['clientDeviceID']) CaptureInfo['UniqueDeviceId'] = CaptureInfo['clientDeviceID'];

                    var jsonStr = JSON.stringify(CaptureInfo, null, 2);
                    console.log("\n[+] 📋 Copying to Clipboard for " + CaptureInfo['deviceName']);
                    console.log(jsonStr);

                    var cm = Java.cast(context.getSystemService("clipboard"), ClipboardManager);
                    var label = StringClass.$new("CaptureInfo");
                    var text = StringClass.$new(jsonStr);
                    cm.setPrimaryClip(ClipData.newPlainText(label, text));

                    try {
                        Toast.makeText(context, StringClass.$new("CaptureInfo Copied!"), 0).show();
                    } catch(eToast) {}
                    
                    return true;
                } catch(e) { console.log("Copy Error: " + e); }
            }
            return this.dispatchKeyEvent(event);
        };
        console.log("[+] Volume Up Copy Enabled");
    } catch(e) { console.log("Key hook error: " + e); }

});
