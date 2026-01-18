const crypto = require('crypto');

/**
 * 生成 ThreatMetrix tmxSessionId
 * @returns {string} 32位字符的 tmxSessionId
 */
function generateTmxSessionId() {
    // 生成32字节的随机数据
    const randomBytes = crypto.randomBytes(24);
    
    // 转换为base64，然后移除特殊字符，只保留字母和数字
    const base64 = randomBytes.toString('base64')
        .replace(/\+/g, '')  // 移除 +
        .replace(/\//g, '')  // 移除 /
        .replace(/=/g, '')   // 移除 =
        .toLowerCase();      // 转换为小写
    
    // 确保长度为32位
    return base64.substring(0, 32);
}

// 测试函数
function test() {
    const sessionId = generateTmxSessionId();
    console.log('Generated tmxSessionId:', sessionId);
    console.log('Length:', sessionId.length);
}

// 运行测试
test();

module.exports = {
    generateTmxSessionId
}; 