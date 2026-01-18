// prevent_exit.js - 专门用于防止应用退出的 Frida 脚本

Java.perform(function() {
    console.log("[*] 开始加载防止退出脚本...");

    // 拦截所有可能的退出点
    function hookExitPoints() {
        // 1. Activity 相关方法
        var Activity = Java.use('android.app.Activity');
        
        // finish() 方法
        Activity.finish.overload().implementation = function() {
            console.log("[+] 拦截 Activity.finish()");
            return;
        };
        
        Activity.finish.overload('int').implementation = function(resultCode) {
            console.log("[+] 拦截 Activity.finish(int)");
            return;
        };
        
        // finishAffinity()
        if (Activity.finishAffinity) {
            Activity.finishAffinity.implementation = function() {
                console.log("[+] 拦截 Activity.finishAffinity");
                return;
            };
        }
        
        // finishAndRemoveTask()
        if (Activity.finishAndRemoveTask) {
            Activity.finishAndRemoveTask.implementation = function() {
                console.log("[+] 拦截 Activity.finishAndRemoveTask");
                return;
            };
        }
        
        // onDestroy()
        Activity.onDestroy.implementation = function() {
            console.log("[+] 拦截 Activity.onDestroy");
            return;
        };
        
        // moveTaskToBack()
        Activity.moveTaskToBack.implementation = function(nonRoot) {
            console.log("[+] 拦截 Activity.moveTaskToBack");
            return false;
        };

        // 2. Process 相关方法
        var Process = Java.use('android.os.Process');
        
        Process.killProcess.implementation = function(pid) {
            console.log("[+] 拦截 Process.killProcess: " + pid);
            return;
        };
        
        if (Process.sendSignal) {
            Process.sendSignal.implementation = function(pid, signal) {
                console.log("[+] 拦截 Process.sendSignal: pid=" + pid + ", signal=" + signal);
                return;
            };
        }

        // 3. System 相关方法
        var System = Java.use('java.lang.System');
        
        System.exit.implementation = function(status) {
            console.log("[+] 拦截 System.exit: " + status);
            return;
        };
        
        // 4. Runtime 相关方法
        var Runtime = Java.use('java.lang.Runtime');
        
        Runtime.exit.implementation = function(status) {
            console.log("[+] 拦截 Runtime.exit: " + status);
            return;
        };
        
        if (Runtime.halt) {
            Runtime.halt.implementation = function(status) {
                console.log("[+] 拦截 Runtime.halt: " + status);
                return;
            };
        }

        // 5. Application 相关方法
        var Application = Java.use('android.app.Application');
        
        Application.onTerminate.implementation = function() {
            console.log("[+] 拦截 Application.onTerminate");
            return;
        };

        // 6. SecurityManager 相关方法
        var SecurityManager = Java.use('java.lang.SecurityManager');
        
        SecurityManager.checkExit.implementation = function(status) {
            console.log("[+] 拦截 SecurityManager.checkExit: " + status);
            return;
        };

        // 7. ActivityManager 相关方法
        try {
            var ActivityManager = Java.use('android.app.ActivityManager');
            
            if (ActivityManager.forceStopPackage) {
                ActivityManager.forceStopPackage.implementation = function(packageName) {
                    console.log("[+] 拦截 ActivityManager.forceStopPackage: " + packageName);
                    return;
                };
            }
        } catch (e) {
            console.log("[-] ActivityManager hook 失败: " + e);
        }

        // 8. 异常处理
        var Thread = Java.use('java.lang.Thread');
        Thread.getUncaughtExceptionHandler.implementation = function() {
            console.log("[+] 拦截异常处理");
            return null;
        };

        // 9. Native 方法退出处理
        try {
            Interceptor.attach(Module.findExportByName(null, "exit"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 native exit 调用");
                    return 0;
                }
            });
        } catch (e) {
            console.log("[-] Native exit hook 失败: " + e);
        }

        try {
            Interceptor.attach(Module.findExportByName(null, "_exit"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 native _exit 调用");
                    return 0;
                }
            });
        } catch (e) {
            console.log("[-] Native _exit hook 失败: " + e);
        }
    }

    // 保持主线程运行
    function keepAlive() {
        var Handler = Java.use('android.os.Handler');
        var Looper = Java.use('android.os.Looper');
        var handler = Handler.$new(Looper.getMainLooper());
        
        var runnable = Java.registerClass({
            name: 'com.example.KeepAliveRunnable',
            implements: [Java.use('java.lang.Runnable')],
            methods: {
                run: function() {
                    console.log("[*] 保持应用运行中...");
                    handler.postDelayed(this, 1000);
                }
            }
        });
        
        handler.post(runnable.$new());
    }

    // 主函数
    function main() {
        console.log("[*] 开始防止应用退出...");
        hookExitPoints();
        keepAlive();
        console.log("[*] 防止应用退出设置完成");
    }

    // 延迟执行主函数，确保应用完全启动
    setTimeout(main, 0);
}); 