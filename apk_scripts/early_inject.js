const frida = require('frida');
const fs = require('fs');

async function earlyInject() {
    try {
        // 1. 连接设备
        const device = await frida.getUsbDevice();
        console.log('[+] Connected to device');

        // 2. 使用 spawn 启动应用但不恢复执行
        const pid = await device.spawn(['com.example.app']);
        console.log('[+] App spawned with PID:', pid);

        // 3. 立即附加到进程
        const session = await device.attach(pid);
        console.log('[+] Attached to process');

        // 4. 加载脚本
        const script = await session.createScript(fs.readFileSync('bypass.js', 'utf8'));
        console.log('[+] Script loaded');

        // 5. 创建消息处理
        script.message.connect(message => {
            if (message.type === 'send') {
                console.log('[*]', message.payload);
            } else if (message.type === 'error') {
                console.error('[!]', message.stack);
            }
        });

        // 6. 加载脚本
        await script.load();
        console.log('[+] Script loaded successfully');

        // 7. 恢复进程执行
        await device.resume(pid);
        console.log('[+] Process resumed');

    } catch (e) {
        console.error('[-] Error:', e);
    }
}

earlyInject();
