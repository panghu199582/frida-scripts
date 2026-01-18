
// 标准 TOTP 算法验证脚本 (Node.js / Frida 通用逻辑)
// 只要把这里的 KEY 换成您抓到的，就能算 OTP

Java.perform(function() {
    console.log("[*] 🧮 正在验证 TOTP 计算...");

    // 1. 您的密钥 (从日志里复制的)
    var KEY_HEX = "911093a7ee5d4348394306495fee232bcf265a6c8f7ec6ffb0db576d3b36ae50";
    
    // 2. 当前时间步 (Time / 30)
    var timeStepLong = Math.floor(new Date().getTime() / 1000 / 30);
    // 这里我们手动转成 Java 的 大端 8字节
    // 因为 JS 位运算只能处理 32位，所以我们用 Java 库来辅助，确保准确
    
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        var Mac = Java.use("javax.crypto.Mac");
        var Integer = Java.use("java.lang.Integer");
        var ByteBuffer = Java.use("java.nio.ByteBuffer");
        
        // 还原 Key
        var keyBytes = hexToBytes(KEY_HEX);
        var keySpec = SecretKeySpec.$new(keyBytes, "HmacSHA256"); // 注意算法是 SHA256
        
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        
        // 构造输入: 8字节的时间计数器
        var buffer = ByteBuffer.allocate(8);
        buffer.putLong(timeStepLong);
        var inputData = buffer.array();
        
        // 计算 HMAC
        var hash = mac.doFinal(inputData);
        
        // Truncate (生成 6 位 OTP)
        var offset = hash[hash.length - 1] & 0xf;
        var binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);
            
        var otp = binary % 1000000;
        
        // 补零
        var otpStr = otp.toString();
        while (otpStr.length < 6) otpStr = "0" + otpStr;
        
        console.log("\n=================================");
        console.log("⌚️ Current Time Step: " + timeStepLong);
        console.log("🔑 Used Key (Hex)    : " + KEY_HEX);
        console.log("🎁 CALCULATED OTP    : " + otpStr);
        console.log("=================================\n");
        
    } catch(e) {
        console.log("[-] Calculation Error: " + e);
    }
    
    // JS Helper
    function hexToBytes(hex) {
        var bytes = [];
        for (var c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        // 转成 Java byte[] 需要特殊处理吗？Frida 会自动把 JS Array 转为 byte[] 吗？
        // Frida 的 Java.use 接收 JS 数组通常会自动转，但最好用 Java Array
        var JByteArray = Java.use("[B");
        var jBytes = Java.array('byte', bytes); // Correct way in Frida
        return jBytes;
    }
});
