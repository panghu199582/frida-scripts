const crypto = require('crypto');

// 1. Inputs from the Log
const keyBase64 = "yjEBnBr+JqIGT+FvXU773mJXkpIvdkY/joqtw0/YI+0=";
const ivHex = "7f1b041c7586c6ba094c913725eeb039";
const expectedOutputBase64 = "QYn2AXsyJ4lQqzSxK5zI3MCg4ShmCrYaDD4o8Trhzkn3YA5ur+lemvmKBqpM/OB68p9c8TJNZe35uXH3VMRL8Gaj2YALPZ6xQsha8zMFdKA3JRxFQPV8epAICUSSIXq7teE127J/HIsKQOsW0CgVIcWy5Pf5u12t0TVGkM5F2mBX2Pho0/w2mlp8G3cpbOiBJ35bDw8F5a9zYfiAnSHaNHtkF8mQ9Akluejga8J0pn5Uy2W7ts3m559CYYo6t4nV8xnRdPNrFAIbnaZ9O+HTgaE2f2I/rJMZDl/1bNMS8XEHLOBaYD1yY7m3Whij1aPd6hoPJGKuhfHdjdMApU1TWzzgXYGTJ76+Q9h+77r0F56o0Xeo6vxgdd1Vx9OOsKP52of6hZkB0ODT/Zs/yy+MGdVbe7DzbUByjIgNgLcPJQvQZE6JxScvlHkPqwifIJsBRMEyQP6mDY4hAhLmuHwYkq+Q49VFNuBh2rAOrp1eER6l3OUcIIkH6xH8SBpbaKQEdxXvsquF2EOJgLiQMEicmWekKKLdvvEWk1mWkW1RUhhgXzUGjjcH0uXDjQHgaZLhyDvCQ2WZNKUGspD2+kkeoLO7yaZXW+2+gm8erZfvnofyPP4jyQFBcqFo+pgKWVNyQltMdOl35anU2OwqrFNI/N3Kxxpm50La3vO3vs2LYrPOqit25SLNjK6W+d/p0jzEIPJ7IXv49n4sJ/6qTzR5v1Ty4BFE+VC5/baPoF0HvF1XoKf6jHXbD4Wlulx359vgzVVwdVcxPIAqfF+UnckZWzMvthCs30DvLQeNoSCdBViqDqigEJREfpsPfYdRoXb8G4RPJzO0OIp+U1Z+QCBS/wdxUQksFZVqO3kTAuoSfCF9mZypADcQX0E3hGrQhwqS08/GxfNIsOGtPhOymmwN27Dlka1xRAikMl1bWX/885yuzCZGfC0XHpmP2XRn+SzwWUd+muAVDviZcFbchp22mqjaegJu7hfYVpiCIzJOeYlSbuRfFvevmShX9o1b5+xgWzgdt/oCYHqe92PoKiwaEpksJKQg9c+i6g1Oj1ofA6In7pHJyQPS1mQlu6Ag19am4/rMT9ZV3Mec4d6GYlpqNrLcuhg9p0pjYc7ckVqHRk1LvnIQlufFoniFSDQK56QCbX1xJV270ZwyBoP1j7kESeP//FVm6UveaEAG4cWVASTPgX12SiTeghgBhu5huIN67FW0QP1KNmbXgBgDsQeUbJNJs9WJaPrZ6OnjoyhWQsTMlNYYCtVjfEMz3/HOavsbMR6eK8UI7Ed9NSbNsF6IbWdMD52DEVs0ogXW8s6Ca0aDXhJyUcpm0n5RwhGdtFWA+GD0p0NrSvbJvjrWuDCnN1APHX/GZsMU5/t765q9RQWkBtQFKv9j1GoFjan8PePry801A/2F8tYR4Miy1oys+QtIbiqfASyoQEqkbF7SsVKYb+WIkJsa85wmZuxhT/QhjaXf0klrCoGHEsRGbV9BlmiI1bGl/Ua3ymT4iPNixYpIMapDhAtndrRANDunMgR9gkiMwrYLtyF0wxdafF66zZRQrED/HmxJSgdu6WCmAN6x4CU0Jol5j4qHQZCebb6xM9A5+2Fe1cDw25VKfTTsuS/FCY+VT32IW/wl4oVFXFysr2HNZePOKDhghq2V/6jP5bBi+prNjLOKNrJQIpBICNHVAmD7LbsydITXVnfdWszgZ9zrByL2+jlN90PkR8RtQaf0qkaQJdPP0gBrU2BVjA0jd79hibYr6mgIbamZ2QbBLHA8qQwtile1Z+ufwgwztGDcGSfCrJzUNaIj76E4CDX8k5vGNwzrfwcmlMKd2tfmzK4mtvnJn9S8oGvWqRKCPahRrHOS/5rnIWChtclyiBqXkLcrJUCzg6YyWYZbqHkIcGDhn2UlUJn0+ObDZLexEp8DCQIOu6M4fvTSUzfJlg==";

// The JSON exactly as copied from your request, but ensuring literal \u003d for Gson compatibility
let plaintext = `{"devSeq":84,"clientDeviceID":"a2a04ece-db28-353c-900f-5bc7cb8f56ed","appName":"MOBILE","devicePubKey":"PFJTQUtleVZhbHVlPjxNb2R1bHVzPjdjVzc4cXNDMHFGcm9GcnZWdDRZNmIrWFE3a0oxRUZsMWY2UWdHRVo1blMzNVB1b2pPT2NMMk9nWFpWVnQ5eWFsakRvenJZb3UyS0NQQStlT0d5d0xSaVcxb3BMSHhvMFltaVJNeXkwKzZ3SUNtcENZUnB2Vi9GVmFsdG5RUElndS9UZUp2Vm9uU1c3eFJTTVRtSGR0U2h4ZnN3R1JGK0FkemlzYWp0QXltdGFwZ2lFd0NScFVlbnVEQjBCZllULzhicTdnbmNpaDZXU241ZFQxb0d0aXBoZ1lqeGRSYXVNbWpEVEhrc0VHL1lMTHllcVFhclBBazRUdlIwSXZISkJVd3ZKTm1YQWlFUHY4Y25ZUkVLc2VXa05IVnlUamM4bnY2NnAzaEhjYkxyMWF2UEl2dzdldnN0VUlFa0IyR0xITWs2aVk3YXpUYXdsYnZKcTBQWHhDUT09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==","deviceName":"Pixel 6a","version":"3.2.9","language":"vi-vn","passWord":"cftufdt","uniqueNo":"","username":"0855547","gcmId":"d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg","userID":"0855547","sessionDES":"u3OKQWnNNQFXnvbZ/i5NyW8WkCWSVS4AMsowX0CbBFjysK7+F8mEY5ExhaOX9la+o9dtloA5JAehkD/bxRcsg6iph2EDpxhWYF3IFCuDArpildfGb4gYqcPuC0APttWfX+cZ/ewfIn9lQJ1v8HRsm1z8JnLXjMN4DMi1y1MWu5Jgwq7RCH2U+Fhcu11NhkqVWYLOVoCDIbCvA/vWhkGc+2HtDAVCKnweTM/fqiZqRicxMjz0zsR0vRCH5pt2Bq/3q8xiJQ4RcBS9Gfb34W+jVtuwA/3EaEVY849WXYSs9guZakb4fFtHDOLhvhoooLCOqR+KIpUCKJPQ83VzhJQngg==","sms_otp":"","bioPassword":"","login_type":"flexi_app","isRoot":"false","Channel":"MOBILE","encrypt":false,"osType":"AND"}`;

// Apply Gson Escaping: = -> \u003d
plaintext = plaintext.replace(/=/g, '\\u003d');

// 2. Encryption Function
function runTest() {
    const key = Buffer.from(keyBase64, 'base64');
    const iv = Buffer.from(ivHex, 'hex');

    console.log("Key Length:", key.length); // Should be 32 for AES-256
    console.log("IV Length:", iv.length);   // Should be 16 for AES

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Explicitly disable auto padding if we needed to control it, but default 'PKCS7' is what we want.
    // In Node.js, createCipheriv uses PKCS7 by default.
    
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const outputBase64 = encrypted.toString('base64');
    
    console.log("\nGenerated Ciphertext:");
    console.log(outputBase64);
    
    console.log("\nExpected Ciphertext:");
    console.log(expectedOutputBase64);
    
    if (outputBase64 === expectedOutputBase64) {
        console.log("\n✅ SUCCESS: Encryption matches exactly!");
        
        // Also verify size of IV+Ciphertext for full payload
        const fullPayload = Buffer.concat([iv, encrypted]).toString('base64');
        console.log("\nFull reqBody Payload (IV + Ciphertext):");
        console.log(fullPayload);
    } else {
        console.log("\n❌ FAIL: Output mismatch.");
    }
}

runTest();
