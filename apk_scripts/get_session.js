const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require('path');

// 定义函数签名
const lib = ffi.Library(path.join(__dirname, 'libTMXProfiling-7.2-32-jni.so'), {
    // 假设函数签名，需要根据实际so文件调整
    'Java_com_lexisnexisrisk_threatmetrix_tmxprofiling_vyvyyvv_00024vyyyyyv_getSessionID': ['string', []]
});

try {
    // 调用函数获取sessionId
    const sessionId = lib.Java_com_lexisnexisrisk_threatmetrix_tmxprofiling_vyvyyvv_00024vyyyyyv_getSessionID();
    console.log('Session ID:', sessionId);
} catch (error) {
    console.error('Error calling function:', error);
} 