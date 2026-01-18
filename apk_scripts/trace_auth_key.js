if (ObjC.available) {
    console.log("[*] 开始追踪Adjust认证逻辑...");

    try {
        var ADJRequestHandler = ObjC.classes.ADJRequestHandler;
        if (ADJRequestHandler) {
            // Hook buildAuthorizationHeader
            var authMethod2 = ADJRequestHandler['- buildAuthorizationHeader:activityKind:appSecret:'];
            if (authMethod2 && authMethod2.implementation) {
                Interceptor.attach(authMethod2.implementation, {
                    onEnter: function(args) {
                        try {
                            console.log("\n[+] 捕获到buildAuthorizationHeader调用");
                            
                            // 安全地读取参数
                            if (args[2]) {
                                try {
                                    var param1 = new ObjC.Object(args[2]);
                                    console.log("[*] 参数1: " + param1);
                                } catch(e) {
                                    console.log("[*] 参数1: <无法读取>");
                                }
                            }
                            
                            if (args[3]) {
                                try {
                                    var activityKind = new ObjC.Object(args[3]);
                                    console.log("[*] ActivityKind: " + activityKind);
                                } catch(e) {
                                    console.log("[*] ActivityKind: <无法读取>");
                                }
                            }
                            
                            if (args[4]) {
                                try {
                                    var appSecret = new ObjC.Object(args[4]);
                                    console.log("[*] AppSecret: " + appSecret);
                                } catch(e) {
                                    console.log("[*] AppSecret: <无法读取>");
                                }
                            }
                            
                            // 只打印前三层调用栈，避免过深的调用链
                            console.log("[*] 调用栈(前3层):");
                            Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .slice(0, 3)
                                .map(DebugSymbol.fromAddress)
                                .forEach(function(symbol) {
                                    console.log("\t" + symbol);
                                });
                        } catch(e) {
                            console.log("[-] onEnter处理失败: " + e);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                var result = new ObjC.Object(retval);
                                console.log("[*] 返回值: " + result);
                            } else {
                                console.log("[*] 返回值: null");
                            }
                        } catch(e) {
                            console.log("[-] onLeave处理失败: " + e);
                        }
                        console.log("==================");
                    }
                });
                console.log("[+] Hook buildAuthorizationHeader成功");
            }

            // Hook buildAuthorizationHeaderV2
            var authMethod = ADJRequestHandler['- buildAuthorizationHeaderV2:adjSigningId:headersId:nativeVersion:algorithm:'];
            if (authMethod && authMethod.implementation) {
                Interceptor.attach(authMethod.implementation, {
                    onEnter: function(args) {
                        try {
                            console.log("\n[+] 捕获到buildAuthorizationHeaderV2调用");
                            
                            // 安全地读取参数
                            if (args[2]) {
                                try {
                                    var param1 = new ObjC.Object(args[2]);
                                    console.log("[*] 参数1: " + param1);
                                } catch(e) {
                                    console.log("[*] 参数1: <无法读取>");
                                }
                            }
                            
                            if (args[3]) {
                                try {
                                    var signingId = new ObjC.Object(args[3]);
                                    console.log("[*] SigningId: " + signingId);
                                } catch(e) {
                                    console.log("[*] SigningId: <无法读取>");
                                }
                            }
                            
                            if (args[4]) {
                                try {
                                    var headersId = new ObjC.Object(args[4]);
                                    console.log("[*] HeadersId: " + headersId);
                                } catch(e) {
                                    console.log("[*] HeadersId: <无法读取>");
                                }
                            }
                            
                            if (args[5]) {
                                try {
                                    var nativeVersion = new ObjC.Object(args[5]);
                                    console.log("[*] NativeVersion: " + nativeVersion);
                                } catch(e) {
                                    console.log("[*] NativeVersion: <无法读取>");
                                }
                            }
                            
                            if (args[6]) {
                                try {
                                    var algorithm = new ObjC.Object(args[6]);
                                    console.log("[*] Algorithm: " + algorithm);
                                } catch(e) {
                                    console.log("[*] Algorithm: <无法读取>");
                                }
                            }
                            
                            // 只打印前三层调用栈
                            console.log("[*] 调用栈(前3层):");
                            Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .slice(0, 3)
                                .map(DebugSymbol.fromAddress)
                                .forEach(function(symbol) {
                                    console.log("\t" + symbol);
                                });
                        } catch(e) {
                            console.log("[-] onEnter处理失败: " + e);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                var result = new ObjC.Object(retval);
                                console.log("[*] 返回值: " + result);
                            } else {
                                console.log("[*] 返回值: null");
                            }
                        } catch(e) {
                            console.log("[-] onLeave处理失败: " + e);
                        }
                        console.log("==================");
                    }
                });
                console.log("[+] Hook buildAuthorizationHeaderV2成功");
            }
        } else {
            console.log("[-] 未找到ADJRequestHandler类");
        }
    } catch(e) {
        console.log("[-] Hook失败: " + e);
    }
} else {
    console.log("[-] Objective-C Runtime不可用");
}