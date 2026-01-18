// prevent_native_exit.js - 专门用于处理native层退出的 Frida 脚本

Java.perform(function() {
    console.log("[*] 开始加载native层防护脚本...");

    // 拦截 native 方法调用
    function hookNativeMethods() {
        // 拦截 System.load 和 System.loadLibrary
        var System = Java.use('java.lang.System');
        
        // 修复重载问题
        System.load.overload('java.lang.String').implementation = function(filename) {
            console.log("[+] 拦截 System.load: " + filename);
            return;
        };
        
        System.loadLibrary.overload('java.lang.String').implementation = function(library) {
            console.log("[+] 拦截 System.loadLibrary: " + library);
            return;
        };

        // 拦截 Runtime.load 和 Runtime.loadLibrary
        var Runtime = Java.use('java.lang.Runtime');
        
        // 修复重载问题
        Runtime.load.overload('java.lang.String').implementation = function(filename) {
            console.log("[+] 拦截 Runtime.load: " + filename);
            return;
        };
        
        Runtime.loadLibrary.overload('java.lang.String').implementation = function(library) {
            console.log("[+] 拦截 Runtime.loadLibrary: " + library);
            return;
        };
    }

    // 拦截 native 崩溃
    function interceptCrashes() {
        // 拦截 SIGABRT
        try {
            Interceptor.attach(Module.findExportByName(null, "abort"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 SIGABRT");
                    return 0;
                }
            });
            console.log("[+] 成功hook SIGABRT");
        } catch(e) {
            console.log("[-] Hook SIGABRT失败: " + e);
        }

        // 拦截 SIGSEGV
        try {
            var sigsegv = Module.findExportByName(null, "sigsegv");
            if (sigsegv) {
                Interceptor.attach(sigsegv, {
                    onEnter: function(args) {
                        console.log("[+] 拦截 SIGSEGV");
                        return 0;
                    }
                });
                console.log("[+] 成功hook SIGSEGV");
            }
        } catch(e) {
            console.log("[-] Hook SIGSEGV失败: " + e);
        }

        // 拦截 exit
        try {
            Interceptor.attach(Module.findExportByName(null, "exit"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 exit");
                    return 0;
                }
            });
            console.log("[+] 成功hook exit");
        } catch(e) {
            console.log("[-] Hook exit失败: " + e);
        }

        // 拦截 _exit
        try {
            Interceptor.attach(Module.findExportByName(null, "_exit"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 _exit");
                    return 0;
                }
            });
            console.log("[+] 成功hook _exit");
        } catch(e) {
            console.log("[-] Hook _exit失败: " + e);
        }

        // 拦截 kill
        try {
            Interceptor.attach(Module.findExportByName(null, "kill"), {
                onEnter: function(args) {
                    console.log("[+] 拦截 kill");
                    return 0;
                }
            });
            console.log("[+] 成功hook kill");
        } catch(e) {
            console.log("[-] Hook kill失败: " + e);
        }
    }

    // 监控线程池
    function monitorThreadPools() {
        try {
            var ThreadPoolExecutor = Java.use('java.util.concurrent.ThreadPoolExecutor');
            ThreadPoolExecutor.execute.implementation = function(runnable) {
                console.log("[+] 监控到线程池执行任务");
                try {
                    if (runnable && runnable.getClass) {
                        var className = runnable.getClass().getName();
                        console.log("[*] 任务类名: " + className);
                        if (className.includes("eetce")) {
                            console.log("[!] 检测到可疑任务");
                            return;
                        }
                    }
                } catch(e) {
                    console.log("[-] 获取任务类名失败: " + e);
                }
                return this.execute(runnable);
            };
            console.log("[+] 成功hook ThreadPoolExecutor");
        } catch(e) {
            console.log("[-] Hook ThreadPoolExecutor失败: " + e);
        }
    }

    // 监控 native 库加载
    function monitorNativeLibraries() {
        try {
            var ClassLoader = Java.use('java.lang.ClassLoader');
            ClassLoader.loadClass.overload('java.lang.String').implementation = function(name) {
                if (name.includes("eetce")) {
                    console.log("[+] 拦截可疑类加载: " + name);
                    return null;
                }
                return this.loadClass(name);
            };
            console.log("[+] 成功hook ClassLoader");
        } catch(e) {
            console.log("[-] Hook ClassLoader失败: " + e);
        }
    }

    // 拦截 native 方法调用
    function hookSpecificNativeMethods() {
        try {
            // 尝试找到并hook可疑的native方法
            var suspiciousClass = Java.use('eetce.nflxfw');
            if (suspiciousClass.hcrmh) {
                suspiciousClass.hcrmh.implementation = function() {
                    console.log("[+] 拦截 hcrmh native方法");
                    return;
                };
                console.log("[+] 成功hook hcrmh");
            }
            
            suspiciousClass = Java.use('eetce.ghtufm');
            if (suspiciousClass.rtrzco) {
                suspiciousClass.rtrzco.implementation = function() {
                    console.log("[+] 拦截 rtrzco native方法");
                    return;
                };
                console.log("[+] 成功hook rtrzco");
            }
            
            suspiciousClass = Java.use('eetce.yoyz');
            if (suspiciousClass.run) {
                suspiciousClass.run.implementation = function() {
                    console.log("[+] 拦截 yoyz.run");
                    return;
                };
                console.log("[+] 成功hook yoyz.run");
            }
        } catch(e) {
            console.log("[-] Hook可疑native方法失败: " + e);
        }
    }

    // 监控进程状态
    function monitorProcessState() {
        try {
            var Process = Java.use('android.os.Process');
            Process.myPid.implementation = function() {
                var pid = this.myPid();
                console.log("[+] 当前进程PID: " + pid);
                return pid;
            };
            console.log("[+] 成功hook Process.myPid");
        } catch(e) {
            console.log("[-] Hook Process.myPid失败: " + e);
        }
    }

    // 拦截native崩溃信号
    function hookNativeSignals() {
        try {
            // 拦截SIGABRT
            var sigabrt = Module.findExportByName(null, "sigabrt");
            if (sigabrt) {
                Interceptor.attach(sigabrt, {
                    onEnter: function(args) {
                        console.log("[+] 拦截SIGABRT信号");
                        return 0;
                    }
                });
                console.log("[+] 成功hook SIGABRT信号");
            }
            
            // 拦截SIGSEGV - 使用新的方法
            var sigsegv = Module.findExportByName(null, "sigsegv");
            if (sigsegv) {
                Interceptor.attach(sigsegv, {
                    onEnter: function(args) {
                        console.log("[+] 拦截SIGSEGV信号");
                        return 0;
                    }
                });
                console.log("[+] 成功hook SIGSEGV信号");
            } else {
                // 尝试其他可能的符号名
                var sigsegv_alt = Module.findExportByName(null, "sigsegv_handler");
                if (sigsegv_alt) {
                    Interceptor.attach(sigsegv_alt, {
                        onEnter: function(args) {
                            console.log("[+] 拦截SIGSEGV信号 (alt)");
                            return 0;
                        }
                    });
                    console.log("[+] 成功hook SIGSEGV信号 (alt)");
                }
            }

            // 拦截SIGBUS
            var sigbus = Module.findExportByName(null, "sigbus");
            if (sigbus) {
                Interceptor.attach(sigbus, {
                    onEnter: function(args) {
                        console.log("[+] 拦截SIGBUS信号");
                        return 0;
                    }
                });
                console.log("[+] 成功hook SIGBUS信号");
            }

            // 拦截SIGILL
            var sigill = Module.findExportByName(null, "sigill");
            if (sigill) {
                Interceptor.attach(sigill, {
                    onEnter: function(args) {
                        console.log("[+] 拦截SIGILL信号");
                        return 0;
                    }
                });
                console.log("[+] 成功hook SIGILL信号");
            }
        } catch(e) {
            console.log("[-] Hook信号失败: " + e);
        }
    }

    // 监控内存访问
    function monitorMemoryAccess() {
        try {
            // 监控可疑的内存区域
            var suspiciousModules = ["libeetce.so", "libnative.so", "libdgiohyse.so"];
            suspiciousModules.forEach(function(moduleName) {
                try {
                    var module = Module.findBaseAddress(moduleName);
                    if (module) {
                        console.log("[+] 找到可疑模块: " + moduleName);
                        // 获取模块大小
                        var moduleSize = 0;
                        try {
                            moduleSize = module.size;
                            if (moduleSize > 0) {
                                // 只保护关键区域，而不是整个模块
                                var criticalRegions = [
                                    { offset: 0x20e14c, size: 0x1000 },  // 崩溃位置
                                    { offset: 0x21e9d8, size: 0x1000 },  // 调用栈 #01
                                    { offset: 0x222ca4, size: 0x1000 }   // 调用栈 #02
                                ];
                                
                                criticalRegions.forEach(function(region) {
                                    try {
                                        var startAddr = module.add(region.offset);
                                        Memory.protect(startAddr, region.size, 'rw-');
                                        console.log("[+] 已保护关键区域: " + moduleName + " @ 0x" + region.offset.toString(16));
                                        
                                        // 监控这个区域的内存访问
                                        MemoryAccessMonitor.enable(startAddr, region.size, {
                                            onAccess: function(details) {
                                                console.log("[!] 检测到内存访问:");
                                                console.log("    地址: 0x" + details.address.toString(16));
                                                console.log("    操作: " + details.operation);
                                                console.log("    来自: 0x" + details.from.toString(16));
                                                
                                                // 如果是写操作，阻止它
                                                if (details.operation === 'write') {
                                                    console.log("[+] 阻止写操作");
                                                    return false;
                                                }
                                                return true;
                                            }
                                        });
                                    } catch(e) {
                                        console.log("[-] 保护关键区域失败: " + moduleName + " @ 0x" + region.offset.toString(16) + " - " + e);
                                    }
                                });
                            } else {
                                console.log("[-] 模块大小无效: " + moduleName);
                            }
                        } catch(e) {
                            console.log("[-] 获取模块大小失败: " + moduleName + " - " + e);
                        }
                    } else {
                        console.log("[-] 未找到模块: " + moduleName);
                    }
                } catch(e) {
                    console.log("[-] 处理模块失败: " + moduleName + " - " + e);
                }
            });
        } catch(e) {
            console.log("[-] 监控内存访问失败: " + e);
        }
    }

    // 监控Binder通信
    function monitorBinderCommunication() {
        try {
            var Binder = Java.use('android.os.Binder');
            Binder.execTransact.implementation = function(code, data, reply, flags) {
                console.log("[+] 拦截Binder通信: code=" + code);
                if (code === 54) {
                    console.log("[!] 检测到可疑Binder调用");
                    return true; // 修复：返回boolean类型
                }
                return this.execTransact(code, data, reply, flags);
            };
            console.log("[+] 成功hook Binder.execTransact");
        } catch(e) {
            console.log("[-] Hook Binder.execTransact失败: " + e);
        }
    }

    // 监控线程创建
    function monitorThreadCreation() {
        try {
            var Thread = Java.use('java.lang.Thread');
            Thread.start.implementation = function() {
                console.log("[+] 监控到新线程创建");
                try {
                    var threadName = this.getName();
                    console.log("[*] 线程名: " + threadName);
                    if (threadName.includes("d.process.media") || 
                        threadName.includes("com.android.nfc") ||
                        threadName.includes("inputmethod.latin")) {
                        console.log("[!] 检测到可疑线程");
                        return;
                    }
                } catch(e) {
                    console.log("[-] 获取线程名失败: " + e);
                }
                return this.start();
            };
            console.log("[+] 成功hook Thread.start");
        } catch(e) {
            console.log("[-] Hook Thread.start失败: " + e);
        }
    }

    // 监控输入法服务
    function monitorInputMethodService() {
        try {
            var InputMethodService = Java.use('android.inputmethodservice.InputMethodService');
            if (InputMethodService) {
                InputMethodService.onCreate.implementation = function() {
                    console.log("[+] 拦截输入法服务创建");
                    return;
                };
                console.log("[+] 成功hook InputMethodService.onCreate");
            }
        } catch(e) {
            console.log("[-] Hook InputMethodService失败: " + e);
        }
    }

    // 监控native库加载
    function monitorNativeLibraryLoading() {
        try {
            // 拦截dlopen调用
            Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
                onEnter: function(args) {
                    var path = args[0].readCString();
                    if (path) {
                        console.log("[+] 正在加载native库: " + path);
                        // 检查是否是可疑的库
                        if (path.includes("eetce") || path.includes("dgiohyse")) {
                            console.log("[!] 检测到可疑库加载: " + path);
                            // 阻止加载
                            args[0] = ptr(0);
                        }
                    }
                }
            });

            // 监控System.load和System.loadLibrary
            var System = Java.use('java.lang.System');
            System.load.implementation = function(filename) {
                console.log("[+] System.load: " + filename);
                if (filename.includes("eetce") || filename.includes("dgiohyse")) {
                    console.log("[!] 阻止加载可疑库: " + filename);
                    return;
                }
                this.load(filename);
            };

            System.loadLibrary.implementation = function(libraryName) {
                console.log("[+] System.loadLibrary: " + libraryName);
                if (libraryName.includes("eetce") || libraryName.includes("dgiohyse")) {
                    console.log("[!] 阻止加载可疑库: " + libraryName);
                    return;
                }
                this.loadLibrary(libraryName);
            };

            console.log("[+] Native库加载监控已启动");
        } catch(e) {
            console.log("[-] 监控native库加载失败: " + e);
        }
    }

    // 处理native层崩溃信号
    function handleNativeSignals() {
        try {
            // 处理SIGABRT信号
            Process.setExceptionHandler(function(details) {
                console.log("[!] 捕获到native异常:");
                console.log("    类型: " + details.type);
                console.log("    地址: 0x" + (details.address ? details.address.toString(16) : "unknown"));
                console.log("    操作: " + (details.operation || "unknown"));
                if (details.memoryAddress) {
                    console.log("    内存地址: 0x" + details.memoryAddress.toString(16));
                }
                
                // 检查是否是空指针访问
                if (details.type === 'access-violation' && 
                    details.address && 
                    (details.address.equals(ptr(0)) || details.address.equals(ptr(0x68)))) {
                    console.log("[+] 检测到空指针访问，尝试修复");
                    // 返回true表示我们已经处理了这个异常
                    return true;
                }
                
                // 对于其他类型的异常，也尝试恢复执行
                return true;
            });

            // 拦截exit和_exit系统调用
            var exitPtr = Module.findExportByName(null, 'exit');
            var _exitPtr = Module.findExportByName(null, '_exit');
            
            if (exitPtr) {
                Interceptor.attach(exitPtr, {
                    onEnter: function(args) {
                        console.log("[!] 拦截到exit调用，状态码: " + args[0].toInt32());
                        // 阻止退出
                        this.context.pc = this.context.pc.add(4);
                    }
                });
            }

            if (_exitPtr) {
                Interceptor.attach(_exitPtr, {
                    onEnter: function(args) {
                        console.log("[!] 拦截到_exit调用，状态码: " + args[0].toInt32());
                        // 阻止退出
                        this.context.pc = this.context.pc.add(4);
                    }
                });
            }

            console.log("[+] Native信号处理已启动");
        } catch(e) {
            console.log("[-] 设置native信号处理失败: " + e);
        }
    }

    // 增强native层保护
    function enhanceNativeProtection() {
        try {
            // 监控native方法调用
            var suspiciousClasses = [
                'com.ncb.bank.eetce.nflxfw.hcrmh',
                'com.ncb.bank.eetce.ghtufm.rtrzco',
                'com.ncb.bank.eetce.yoyz.run'
            ];
            
            suspiciousClasses.forEach(function(className) {
                try {
                    var parts = className.split('.');
                    var currentClass = Java.use(parts[0]);
                    for (var i = 1; i < parts.length; i++) {
                        currentClass = currentClass[parts[i]];
                    }
                    if (currentClass && currentClass.implementation) {
                        currentClass.implementation = function() {
                            console.log("[!] 拦截可疑native方法调用: " + className);
                            return;
                        };
                        console.log("[+] 成功hook: " + className);
                    }
                } catch(e) {
                    console.log("[-] Hook失败: " + className + " - " + e);
                }
            });

            // 监控内存访问
            var suspiciousModules = [
                'libdgiohyse.so',
                'libnative.so',
                'libeetce.so'
            ];
            
            suspiciousModules.forEach(function(moduleName) {
                try {
                    var module = Module.findBaseAddress(moduleName);
                    if (module) {
                        console.log("[+] 找到可疑模块: " + moduleName);
                        try {
                            // 获取模块大小
                            var moduleSize = module.size;
                            if (moduleSize > 0) {
                                Memory.protect(module, moduleSize, 'rw-');
                                console.log("[+] 已保护模块内存: " + moduleName + " (大小: " + moduleSize + ")");
                            } else {
                                console.log("[-] 模块大小无效: " + moduleName);
                            }
                        } catch(e) {
                            console.log("[-] 保护模块内存失败: " + moduleName + " - " + e);
                        }
                    }
                } catch(e) {
                    console.log("[-] 保护模块失败: " + moduleName + " - " + e);
                }
            });

            console.log("[+] Native层保护增强完成");
        } catch(e) {
            console.log("[-] 增强native层保护失败: " + e);
        }
    }

    // 特殊处理libdgiohyse.so
    function handleDgiohyseLibrary() {
        try {
            var dgiohyse = Module.findBaseAddress('libdgiohyse.so');
            if (dgiohyse) {
                console.log("[+] 找到libdgiohyse.so，地址: " + dgiohyse);
                
                try {
                    // 获取模块大小
                    var moduleSize = dgiohyse.size;
                    if (moduleSize > 0) {
                        // 保护关键内存区域
                        Memory.protect(dgiohyse, moduleSize, 'rw-');
                        console.log("[+] 已保护libdgiohyse.so内存 (大小: " + moduleSize + ")");

                        // 拦截可疑函数
                        var suspiciousOffsets = [
                            0x20e14c,  // 崩溃位置
                            0x21e9d8,  // 调用栈 #01
                            0x222ca4   // 调用栈 #02
                        ];

                        suspiciousOffsets.forEach(function(offset) {
                            try {
                                var targetAddr = dgiohyse.add(offset);
                                Interceptor.attach(targetAddr, {
                                    onEnter: function(args) {
                                        console.log("[!] 拦截libdgiohyse.so可疑函数调用: 0x" + offset.toString(16));
                                        // 修复空指针
                                        if (this.context.x0.equals(ptr(0)) || this.context.x0.equals(ptr(0x68))) {
                                            console.log("[+] 修复空指针访问");
                                            this.context.x0 = ptr(1);  // 使用非空值
                                        }
                                    }
                                });
                                console.log("[+] 成功hook偏移: 0x" + offset.toString(16));
                            } catch(e) {
                                console.log("[-] Hook偏移失败: 0x" + offset.toString(16) + " - " + e);
                            }
                        });
                    } else {
                        console.log("[-] libdgiohyse.so大小无效");
                    }
                } catch(e) {
                    console.log("[-] 处理libdgiohyse.so内存失败: " + e);
                }
            }
        } catch(e) {
            console.log("[-] 处理libdgiohyse.so失败: " + e);
        }
    }

    // 保护线程
    function protectThreads() {
        try {
            // 拦截pthread_create
            var pthread_create = Module.findExportByName(null, 'pthread_create');
            if (pthread_create) {
                Interceptor.attach(pthread_create, {
                    onEnter: function(args) {
                        console.log("[+] 拦截线程创建");
                        // 检查线程函数地址
                        var threadFunc = args[2];
                        if (threadFunc && !threadFunc.isNull()) {
                            try {
                                var module = Process.findModuleByAddress(threadFunc);
                                if (module && module.name && module.name.includes('libdgiohyse.so')) {
                                    console.log("[!] 检测到可疑线程创建");
                                    // 修改线程函数地址为一个安全的地址
                                    args[2] = ptr(1);
                                }
                            } catch(e) {
                                console.log("[-] 检查线程函数失败: " + e);
                            }
                        }
                    }
                });
                console.log("[+] 成功hook pthread_create");
            }

            // 拦截pthread_join
            var pthread_join = Module.findExportByName(null, 'pthread_join');
            if (pthread_join) {
                Interceptor.attach(pthread_join, {
                    onEnter: function(args) {
                        console.log("[+] 拦截线程join");
                        // 防止线程被join
                        if (args[0] && !args[0].isNull()) {
                            args[0] = ptr(1);
                        }
                    }
                });
                console.log("[+] 成功hook pthread_join");
            }

            // 拦截pthread_kill
            var pthread_kill = Module.findExportByName(null, 'pthread_kill');
            if (pthread_kill) {
                Interceptor.attach(pthread_kill, {
                    onEnter: function(args) {
                        console.log("[+] 拦截线程kill");
                        // 防止线程被kill
                        if (args[0] && !args[0].isNull()) {
                            args[0] = ptr(1);
                        }
                    }
                });
                console.log("[+] 成功hook pthread_kill");
            }

            // 拦截pthread_cancel
            var pthread_cancel = Module.findExportByName(null, 'pthread_cancel');
            if (pthread_cancel) {
                Interceptor.attach(pthread_cancel, {
                    onEnter: function(args) {
                        console.log("[+] 拦截线程cancel");
                        // 防止线程被cancel
                        if (args[0] && !args[0].isNull()) {
                            args[0] = ptr(1);
                        }
                    }
                });
                console.log("[+] 成功hook pthread_cancel");
            }
        } catch(e) {
            console.log("[-] 保护线程失败: " + e);
        }
    }

    // 主函数
    function main() {
        console.log("[*] 开始防止native层退出...");
        Java.perform(function() {
            hookNativeMethods();
            monitorThreadPools();
            interceptCrashes();
            monitorMemoryAccess();
            monitorNativeLibraryLoading();
            handleNativeSignals();
            enhanceNativeProtection();
            handleDgiohyseLibrary();
            protectThreads();
            console.log("[+] 设置完成");
        });
    }

    // 延迟执行主函数，确保应用完全启动
    setTimeout(main, 0);
}); 