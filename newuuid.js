Java.perform(function() {
    console.log("\n[***] 启动全方位硬件伪装脚本 [***]");

    var Build = Java.use("android.os.Build");
    var Settings = Java.use("android.provider.Settings$Secure");

    // 生成随机字符串的辅助函数
    function randomString(len) {
        var charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        var randomString = '';
        for (var i = 0; i < len; i++) {
            var randomPoz = Math.floor(Math.random() * charSet.length);
            randomString += charSet.substring(randomPoz, randomPoz + 1);
        }
        return randomString;
    }

    // =======================================================
    // 1. 伪造 Build 类中的静态字段 (最常见指纹)
    // =======================================================
    
    // 伪造序列号 (Serial) - 很多“不变ID”的罪魁祸首
    var FAKE_SERIAL = "SPOOF_" + randomString(10);
    // 伪造型号 (Model)
    var FAKE_MODEL = "Pixel 99 Pro";
    // 伪造厂商
    var FAKE_MANUFACTURER = "Google_Spoofed";
    // 伪造设备指纹 (Build.FINGERPRINT)
    var FAKE_FINGERPRINT = "google/bluejay/bluejay:13/TP1A.220624.014/8819520:user/release-keys";

    // 覆盖静态字段值
    Build.SERIAL.value = FAKE_SERIAL;
    Build.MODEL.value = FAKE_MODEL;
    Build.MANUFACTURER.value = FAKE_MANUFACTURER;
    Build.FINGERPRINT.value = FAKE_FINGERPRINT;
    Build.PRODUCT.value = "bluejay_fake";
    Build.DEVICE.value = "bluejay_fake";
    Build.HARDWARE.value = "tensor_fake";

    console.log("[+] Build.SERIAL 已伪造为: " + FAKE_SERIAL);
    console.log("[+] Build.MODEL  已伪造为: " + FAKE_MODEL);

    // =======================================================
    // 2. 拦截 getSerial() 方法 (Android 8.0+ 的获取方式)
    // =======================================================
    try {
        // 有些系统可能没有这个方法，try-catch 包裹
        Build.getSerial.implementation = function() {
            console.log("[!] 拦截到 getSerial() 调用 -> 返回伪造值");
            return FAKE_SERIAL;
        };
    } catch (e) {
        console.log("[-] getSerial hook error: " + e);
    }

    // =======================================================
    // 3. 拦截 Android ID (再次确保)
    // =======================================================
    var FAKE_ANDROID_ID = randomString(16).toLowerCase();
    Settings.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
        if (name == 'android_id') {
            console.log("[!] 拦截 Android ID 读取 -> 返回: " + FAKE_ANDROID_ID);
            return FAKE_ANDROID_ID;
        }
        return this.getString(resolver, name);
    };
    
    // =======================================================
    // 4. (可选) 拦截 KeyStore 生成，确保不复用任何之前的逻辑
    // =======================================================
    // 如果 App 用 Build.SERIAL 作为 Key 的别名种子，这步会自动生效
});