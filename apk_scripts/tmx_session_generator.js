const crypto = require('crypto');

class TmxSessionGenerator {
    constructor() {
        this.sessionTimeout = 5000; // 5秒超时
        this.lastGeneratedTime = null;
        this.lastSessionId = null;
    }

    /**
     * 生成新的 tmxSessionId
     * @returns {string} 32位字符的 tmxSessionId
     */
    generate() {
        // 生成32字节的随机数据
        const randomBytes = crypto.randomBytes(24);
        
        // 转换为base64，然后移除特殊字符，只保留字母和数字
        const base64 = randomBytes.toString('base64')
            .replace(/\+/g, '')  // 移除 +
            .replace(/\//g, '')  // 移除 /
            .replace(/=/g, '')   // 移除 =
            .toLowerCase();      // 转换为小写
        
        // 确保长度为32位
        const sessionId = base64.substring(0, 32);
        
        // 记录生成时间
        this.lastGeneratedTime = Date.now();
        this.lastSessionId = sessionId;
        
        return sessionId;
    }

    /**
     * 获取当前有效的 tmxSessionId
     * @returns {string} 当前有效的 tmxSessionId
     */
    getCurrentSessionId() {
        const now = Date.now();
        
        // 如果没有生成过，或者已经超时，生成新的
        if (!this.lastGeneratedTime || 
            (now - this.lastGeneratedTime) >= this.sessionTimeout) {
            return this.generate();
        }
        
        return this.lastSessionId;
    }

    /**
     * 检查 tmxSessionId 是否有效
     * @param {string} sessionId 要检查的 tmxSessionId
     * @returns {boolean} 是否有效
     */
    isValid(sessionId) {
        if (!this.lastGeneratedTime || !this.lastSessionId) {
            return false;
        }

        const now = Date.now();
        return sessionId === this.lastSessionId && 
               (now - this.lastGeneratedTime) < this.sessionTimeout;
    }

    /**
     * 获取 tmxSessionId 的剩余有效时间（毫秒）
     * @returns {number} 剩余有效时间
     */
    getRemainingTime() {
        if (!this.lastGeneratedTime) {
            return 0;
        }

        const now = Date.now();
        const elapsed = now - this.lastGeneratedTime;
        return Math.max(0, this.sessionTimeout - elapsed);
    }
}

// 创建生成器实例
const generator = new TmxSessionGenerator();

// 模拟发送请求的函数
function simulateRequest(sessionId) {
    console.log('\n=== 模拟发送请求 ===');
    console.log('使用 tmxSessionId:', sessionId);
    console.log('是否有效:', generator.isValid(sessionId));
    console.log('剩余时间:', generator.getRemainingTime(), 'ms');
}

// 测试函数
async function test() {
    console.log('=== 开始测试 tmxSessionId 生成器 ===\n');

    // 生成第一个 sessionId
    const sessionId1 = generator.generate();
    console.log('1. 生成新的 tmxSessionId:');
    console.log('SessionId:', sessionId1);
    console.log('长度:', sessionId1.length);
    console.log('剩余时间:', generator.getRemainingTime(), 'ms');

    // 立即使用这个 sessionId
    simulateRequest(sessionId1);

    // 等待2秒后再次使用
    console.log('\n2. 等待2秒后...');
    await new Promise(resolve => setTimeout(resolve, 2000));
    simulateRequest(sessionId1);

    // 等待4秒后再次使用（接近超时）
    console.log('\n3. 等待4秒后...');
    await new Promise(resolve => setTimeout(resolve, 2000));
    simulateRequest(sessionId1);

    // 等待6秒后再次使用（已超时）
    console.log('\n4. 等待6秒后...');
    await new Promise(resolve => setTimeout(resolve, 2000));
    simulateRequest(sessionId1);

    // 获取新的 sessionId
    console.log('\n5. 获取新的 sessionId:');
    const sessionId2 = generator.getCurrentSessionId();
    console.log('新的 SessionId:', sessionId2);
    console.log('是否与之前相同:', sessionId1 === sessionId2);
    console.log('剩余时间:', generator.getRemainingTime(), 'ms');

    // 使用新的 sessionId
    simulateRequest(sessionId2);
}

// 运行测试
test().catch(console.error);

module.exports = TmxSessionGenerator; 