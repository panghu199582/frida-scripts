Java.perform(function() {
    console.log('\n=== 开始 Hook ThreatMetrix 库 ===\n');

    // Hook TMXProfiling 类
    var TMXProfiling = Java.use('com.lexisnexisrisk.threatmetrix.TMXProfiling');
    
    // 用于存储最近生成的 tmxSessionId
    var lastSessionId = null;
    var sessionIdCount = 0;
    var lastExpiryTime = null;
    
    // Hook getInstance 方法
    if (TMXProfiling.getInstance) {
        TMXProfiling.getInstance.implementation = function() {
            var instance = this.getInstance();
            console.log('\n[TMXProfiling.getInstance]');
            
            // 获取实例的所有字段
            try {
                var fields = instance.getClass().getDeclaredFields();
                console.log('\nInstance Fields:');
                for (var i = 0; i < fields.length; i++) {
                    fields[i].setAccessible(true);
                    var fieldName = fields[i].getName();
                    var fieldValue = fields[i].get(instance);
                    console.log(fieldName + ':', fieldValue);
                    
                    if (fieldName === 'aaa00610061a0061') {
                        if (lastExpiryTime !== fieldValue) {
                            console.log('\n[Expiry Time Changed]');
                            console.log('Old Value:', lastExpiryTime);
                            console.log('New Value:', fieldValue);
                            console.log('Time:', new Date().toISOString());
                            if (lastExpiryTime) {
                                var diff = fieldValue - lastExpiryTime;
                                console.log('Time Difference (ms):', diff);
                            }
                            lastExpiryTime = fieldValue;
                        }
                    }
                }
            } catch (e) {
                console.log('Error getting fields:', e);
            }

            // 获取实例的所有方法
            try {
                var methods = instance.getClass().getDeclaredMethods();
                console.log('\nInstance Methods:');
                for (var i = 0; i < methods.length; i++) {
                    console.log(methods[i].getName());
                }
            } catch (e) {
                console.log('Error getting methods:', e);
            }

            // 尝试获取可能的 sessionId 字段
            try {
                var possibleFields = ['sessionId', 'tmxSessionId', 'mSessionId', 'mTmxSessionId'];
                for (var i = 0; i < possibleFields.length; i++) {
                    try {
                        var field = instance.getClass().getDeclaredField(possibleFields[i]);
                        field.setAccessible(true);
                        var value = field.get(instance);
                        if (value) {
                            console.log('\nFound possible sessionId field:', possibleFields[i], '=', value);
                        }
                    } catch (e) {
                        // 忽略字段不存在的错误
                    }
                }
            } catch (e) {
                console.log('Error checking sessionId fields:', e);
            }

            // Hook 关键方法
            try {
                // Hook CMeE
                if (instance.CMeE) {
                    instance.CMeE.implementation = function() {
                        console.log('\n[CMeE Called]');
                        console.log('Time:', new Date().toISOString());
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                        var result = this.CMeE.apply(this, arguments);
                        if (result) {
                            console.log('CMeE Result:', result);
                            if (typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                                console.log('Found tmxSessionId in CMeE:', result);
                            }
                        }
                        return result;
                    };
                }

                // Hook DMeE
                if (instance.DMeE) {
                    instance.DMeE.implementation = function() {
                        console.log('\n[DMeE Called]');
                        console.log('Time:', new Date().toISOString());
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                        var result = this.DMeE.apply(this, arguments);
                        if (result) {
                            console.log('DMeE Result:', result);
                            if (typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                                console.log('Found tmxSessionId in DMeE:', result);
                            }
                        }
                        return result;
                    };
                }

                // Hook d00640064d00640064d0064
                if (instance.d00640064d00640064d0064) {
                    instance.d00640064d00640064d0064.implementation = function() {
                        console.log('\n[d00640064d00640064d0064 Called]');
                        console.log('Time:', new Date().toISOString());
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                        var result = this.d00640064d00640064d0064.apply(this, arguments);
                        if (result) {
                            console.log('d00640064d00640064d0064 Result:', result);
                            if (typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                                console.log('Found tmxSessionId in d00640064d00640064d0064:', result);
                            }
                        }
                        return result;
                    };
                }

                // Hook dd0064006400640064d0064
                if (instance.dd0064006400640064d0064) {
                    instance.dd0064006400640064d0064.implementation = function() {
                        console.log('\n[dd0064006400640064d0064 Called]');
                        console.log('Time:', new Date().toISOString());
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                        var result = this.dd0064006400640064d0064.apply(this, arguments);
                        if (result) {
                            console.log('dd0064006400640064d0064 Result:', result);
                            if (typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                                console.log('Found tmxSessionId in dd0064006400640064d0064:', result);
                            }
                        }
                        return result;
                    };
                }

            } catch (e) {
                console.log('Error hooking methods:', e);
            }

            return instance;
        };
    }

    // Hook init 方法
    if (TMXProfiling.init) {
        TMXProfiling.init.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log('\n[TMXProfiling.init]');
                var result = this.init.apply(this, arguments);
                try {
                    if (result && result.toString) {
                        console.log('Result:', result.toString());
                    }
                } catch (e) {
                    console.log('Error in init:', e);
                }
                return result;
            };
        });
    }

    // Hook profile 方法
    if (TMXProfiling.profile) {
        TMXProfiling.profile.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log('\n[TMXProfiling.profile]');
                console.log('Arguments:', JSON.stringify(arguments));
                console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
                var result = this.profile.apply(this, arguments);
                try {
                if (result && typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                        sessionIdCount++;
                        console.log('tmxSessionId #' + sessionIdCount + ':', result);
                        console.log('Time:', new Date().toISOString());
                        if (lastSessionId) {
                            console.log('Previous tmxSessionId:', lastSessionId);
                        }
                        lastSessionId = result;
                    }
                } catch (e) {
                    console.log('Error in profile:', e);
                }
                return result;
            };
        });
    }

    // Hook 内部方法 FsAE
    if (TMXProfiling.FsAE) {
        TMXProfiling.FsAE.implementation = function(i, objArr) {
            console.log('\n[TMXProfiling.FsAE]');
            console.log('Arguments:', JSON.stringify([i, objArr]));
            console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
            var result = this.FsAE(i, objArr);
            try {
            if (result && typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                    sessionIdCount++;
                    console.log('tmxSessionId #' + sessionIdCount + ':', result);
                    console.log('Time:', new Date().toISOString());
                    if (lastSessionId) {
                        console.log('Previous tmxSessionId:', lastSessionId);
                    }
                    lastSessionId = result;
                }
            } catch (e) {
                console.log('Error in FsAE:', e);
            }
            return result;
        };
    }

    // Hook 内部方法 vsAE
    if (TMXProfiling.vsAE) {
        TMXProfiling.vsAE.implementation = function(i, objArr) {
            console.log('\n[TMXProfiling.vsAE]');
            console.log('Arguments:', JSON.stringify([i, objArr]));
            console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
            var result = this.vsAE(i, objArr);
            try {
            if (result && typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                    sessionIdCount++;
                    console.log('tmxSessionId #' + sessionIdCount + ':', result);
                    console.log('Time:', new Date().toISOString());
                    if (lastSessionId) {
                        console.log('Previous tmxSessionId:', lastSessionId);
                    }
                    lastSessionId = result;
                }
            } catch (e) {
                console.log('Error in vsAE:', e);
            }
            return result;
        };
    }

    // Hook 内部类 cccddcc
    try {
        var cccddcc = Java.use('com.lexisnexisrisk.threatmetrix.tmxprofiling.cccddcc');
        if (cccddcc.ddd00640064dd) {
            cccddcc.ddd00640064dd.implementation = function() {
                var result = this.ddd00640064dd.apply(this, arguments);
                try {
                if (result && typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                        sessionIdCount++;
                    console.log('\n[cccddcc.ddd00640064dd]');
                        console.log('tmxSessionId #' + sessionIdCount + ':', result);
                        console.log('Time:', new Date().toISOString());
                        if (lastSessionId) {
                            console.log('Previous tmxSessionId:', lastSessionId);
                        }
                        lastSessionId = result;
                        
                        // 打印调用栈
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                    } else if (result) {
                        if (Java.isJavaObject(result)) {
                            console.log('Result Type:', result.getClass().getName());
                            console.log('Result Value:', result.toString());
                        } else {
                            console.log('Result (non-Java):', result);
                            console.log('Result Type:', typeof result);
                        }
                    }
                } catch (e) {
                    console.log('Error in ddd00640064dd:', e);
                }
                return result;
            };
        }
    } catch (e) {
        // 忽略错误
    }

    // Hook 内部类 cdddddc
    try {
        var cdddddc = Java.use('com.lexisnexisrisk.threatmetrix.tmxprofiling.cdddddc');
        if (cdddddc.vv00760076007600760076) {
            cdddddc.vv00760076007600760076.implementation = function() {
                var result = this.vv00760076007600760076.apply(this, arguments);
                try {
                if (result && typeof result === 'string' && result.length === 32 && /^[a-z0-9]{32}$/.test(result)) {
                        sessionIdCount++;
                    console.log('\n[cdddddc.vv00760076007600760076]');
                        console.log('tmxSessionId #' + sessionIdCount + ':', result);
                        console.log('Time:', new Date().toISOString());
                        if (lastSessionId) {
                            console.log('Previous tmxSessionId:', lastSessionId);
                        }
                        lastSessionId = result;
                        
                        // 打印调用栈
                        console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n'));
                    } else if (result) {
                        if (Java.isJavaObject(result)) {
                            console.log('Result Type:', result.getClass().getName());
                            console.log('Result Value:', result.toString());
                        } else {
                            console.log('Result (non-Java):', result);
                            console.log('Result Type:', typeof result);
                        }
                    }
                } catch (e) {
                    console.log('Error in vv00760076007600760076:', e);
                }
                return result;
            };
        }
    } catch (e) {
        // 忽略错误
    }

    // Hook String 类的构造函数，用于捕获可能的 tmxSessionId 生成
    var String = Java.use('java.lang.String');
    String.$init.overload('[B').implementation = function(bytes) {
        var result = this.$init(bytes);
        try {
            var str = result.toString();
            if (str && str.length === 32 && /^[a-z0-9]{32}$/.test(str)) {
                sessionIdCount++;
                console.log('\n[String Constructor]');
                console.log('tmxSessionId #' + sessionIdCount + ':', str);
                console.log('Time:', new Date().toISOString());
                if (lastSessionId) {
                    console.log('Previous tmxSessionId:', lastSessionId);
                }
                lastSessionId = str;
                console.log('Call Stack:', Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
        } catch (e) {
            // 忽略错误
        }
        return result;
    };

    console.log('\n=== Hook 完成 ===\n');
}); 