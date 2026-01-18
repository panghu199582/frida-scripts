// prevent_guardian_exit.js - 专门用于拦截守护进程和后台服务的 Frida 脚本

Java.perform(function() {
    console.log("[*] 开始加载守护进程拦截脚本...");

    // 拦截 Service 相关方法
    function hookServiceMethods() {
        // 拦截 Service 的停止方法
        var Service = Java.use('android.app.Service');
        Service.stopSelf.overload().implementation = function() {
            console.log("[+] 拦截 Service.stopSelf()");
            return;
        };
        Service.stopSelf.overload('int').implementation = function(startId) {
            console.log("[+] 拦截 Service.stopSelf(int)");
            return;
        };
        Service.stopSelfResult.implementation = function(startId) {
            console.log("[+] 拦截 Service.stopSelfResult");
            return false;
        };

        // 拦截 Service 的绑定方法
        Service.onUnbind.implementation = function(intent) {
            console.log("[+] 拦截 Service.onUnbind");
            return false;
        };

        // 拦截 Service 的销毁方法
        Service.onDestroy.implementation = function() {
            console.log("[+] 拦截 Service.onDestroy");
            return;
        };
    }

    // 拦截 WorkManager 相关方法
    function hookWorkManager() {
        try {
            var WorkManager = Java.use('androidx.work.WorkManager');
            if (WorkManager.cancelAllWork) {
                WorkManager.cancelAllWork.implementation = function() {
                    console.log("[+] 拦截 WorkManager.cancelAllWork");
                    return Java.use('androidx.work.Operation').$new();
                };
            }
            console.log("[+] 成功hook WorkManager");
        } catch(e) {
            console.log("[-] WorkManager hook 失败: " + e);
        }
    }

    // 拦截 AlarmManager 相关方法
    function hookAlarmManager() {
        var AlarmManager = Java.use('android.app.AlarmManager');
        AlarmManager.cancel.overload('android.app.PendingIntent').implementation = function(pendingIntent) {
            console.log("[+] 拦截 AlarmManager.cancel");
            return;
        };
    }

    // 拦截 JobScheduler 相关方法
    function hookJobScheduler() {
        try {
            var JobScheduler = Java.use('android.app.job.JobScheduler');
            JobScheduler.cancel.implementation = function(jobId) {
                console.log("[+] 拦截 JobScheduler.cancel");
                return;
            };
            JobScheduler.cancelAll.implementation = function() {
                console.log("[+] 拦截 JobScheduler.cancelAll");
                return;
            };
            console.log("[+] 成功hook JobScheduler");
        } catch(e) {
            console.log("[-] JobScheduler hook 失败: " + e);
        }
    }

    // 拦截 IPC 通信
    function hookIPC() {
        // 拦截 Binder 通信
        try {
            var Binder = Java.use('android.os.Binder');
            Binder.execTransact.implementation = function(code, dataObj, replyObj, flags) {
                console.log("[+] 拦截 Binder.execTransact: code=" + code);
                // 监控但不阻止正常的IPC通信
                return this.execTransact(code, dataObj, replyObj, flags);
            };
            console.log("[+] 成功hook Binder");
        } catch(e) {
            console.log("[-] Binder hook 失败: " + e);
        }

        // 拦截 Messenger 通信
        try {
            var Handler = Java.use('android.os.Handler');
            Handler.handleMessage.implementation = function(msg) {
                console.log("[+] 拦截 Handler.handleMessage: what=" + msg.what);
                // 检查消息是否包含退出命令
                if (msg.what === 1 || msg.what === 2) { // 假设1和2是退出命令
                    console.log("[*] 拦截到可能的退出消息");
                    return;
                }
                return this.handleMessage(msg);
            };
            console.log("[+] 成功hook Handler");
        } catch(e) {
            console.log("[-] Handler hook 失败: " + e);
        }
    }

    // 拦截进程管理相关方法
    function hookProcessManagement() {
        // 拦截 ActivityManager 的 killBackgroundProcesses
        try {
            var ActivityManager = Java.use('android.app.ActivityManager');
            ActivityManager.killBackgroundProcesses.implementation = function(packageName) {
                console.log("[+] 拦截 ActivityManager.killBackgroundProcesses: " + packageName);
                return;
            };
        } catch(e) {
            console.log("[-] ActivityManager hook 失败: " + e);
        }

        // 拦截 Process 的 killProcess
        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function(pid) {
            console.log("[+] 拦截 Process.killProcess: " + pid);
            return;
        };
    }

    // 监控应用包名相关的所有进程
    function monitorProcesses() {
        try {
            var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
                var cmd = Java.array('java.lang.String', cmdArray);
                console.log("[+] 监控到进程创建: " + cmd.join(' '));
                return this.$init(cmdArray);
            };
        } catch(e) {
            console.log("[-] ProcessBuilder hook 失败: " + e);
        }
    }

    // 保持服务运行
    function keepServicesAlive() {
        try {
            var Context = Java.use('android.content.Context');
            Context.stopService.implementation = function(service) {
                console.log("[+] 拦截 Context.stopService");
                return false;
            };
            
            Context.unbindService.implementation = function(conn) {
                console.log("[+] 拦截 Context.unbindService");
                return;
            };
        } catch(e) {
            console.log("[-] Context hook 失败: " + e);
        }
    }

    // 主函数
    function main() {
        console.log("[*] 开始防止守护进程干扰...");
        
        hookServiceMethods();
        hookWorkManager();
        hookAlarmManager();
        hookJobScheduler();
        hookIPC();
        hookProcessManagement();
        monitorProcesses();
        keepServicesAlive();
        
        console.log("[*] 守护进程防护设置完成");

        // 定期检查服务状态
        setInterval(function() {
            console.log("[*] 服务监控中...");
        }, 2000);
    }

    // 延迟执行主函数，确保应用完全启动
    setTimeout(main, 0);
}); 