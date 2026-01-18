console.log("[+] NetworkEntity 类监控脚本启动");

// 统一日志格式
function logNetwork(type, data) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${type}] ${data}`);
}

// 安全的hook函数
function safeHook(className, methodName, callback) {
    try {
        const clazz = Java.use(className);
        if (clazz && clazz[methodName]) {
            clazz[methodName].implementation = callback;
            logNetwork("HOOK", `成功hook ${className}.${methodName}`);
            return true;
        }
    } catch (e) {
        logNetwork("ERROR", `Hook ${className}.${methodName} 失败: ${e.message}`);
    }
    return false;
}

// 安全的hook重载方法
function safeHookOverload(className, methodName, signature, callback) {
    try {
        const clazz = Java.use(className);
        if (clazz && clazz[methodName]) {
            clazz[methodName].overload(signature).implementation = callback;
            logNetwork("HOOK", `成功hook ${className}.${methodName}(${signature})`);
            return true;
        }
    } catch (e) {
        logNetwork("ERROR", `Hook ${className}.${methodName}(${signature}) 失败: ${e.message}`);
    }
    return false;
}

// 监控 NetworkEntity 类
function hookNetworkEntity() {
    logNetwork("INFO", "开始hook NetworkEntity类...");
    
    const className = "vn.tpb.dao.entities.NetworkEntity";
    
    try {
        const NetworkEntityClass = Java.use(className);
        logNetwork("SUCCESS", `找到类: ${className}`);
        
        // Hook 构造函数
        if (NetworkEntityClass.$init) {
            NetworkEntityClass.$init.implementation = function() {
                try {
                    logNetwork("CONSTRUCTOR", "NetworkEntity 构造函数被调用");
                    logNetwork("OBJECT", `对象地址: ${this.toString()}`);
                } catch (e) {
                    logNetwork("ERROR", `构造函数hook错误: ${e.message}`);
                }
                
                return this.$init();
            };
        }
        
        // Hook 带参数的构造函数
        if (NetworkEntityClass.$init.overloads) {
            NetworkEntityClass.$init.overloads.forEach((overload, index) => {
                try {
                    overload.implementation = function() {
                        try {
                            logNetwork("CONSTRUCTOR", `NetworkEntity 构造函数(${index})被调用`);
                            logNetwork("OBJECT", `对象地址: ${this.toString()}`);
                            
                            // 尝试获取参数信息
                            const args = Array.from(arguments);
                            if (args.length > 0) {
                                logNetwork("PARAMS", `参数: ${args.map(arg => arg ? arg.toString() : 'null').join(', ')}`);
                            }
                        } catch (e) {
                            logNetwork("ERROR", `构造函数(${index}) hook错误: ${e.message}`);
                        }
                        
                        return overload.apply(this, arguments);
                    };
                } catch (e) {
                    logNetwork("ERROR", `构造函数(${index}) hook失败: ${e.message}`);
                }
            });
        }
        
        // Hook 所有公共方法
        const methods = NetworkEntityClass.class.getDeclaredMethods();
        methods.forEach(method => {
            const methodName = method.getName();
            
            // 跳过一些系统方法
            if (methodName.startsWith('access$') || methodName === 'toString' || methodName === 'hashCode' || methodName === 'equals') {
                return;
            }
            
            try {
                if (NetworkEntityClass[methodName]) {
                    NetworkEntityClass[methodName].implementation = function() {
                        try {
                            const args = Array.from(arguments);
                            logNetwork("METHOD", `NetworkEntity.${methodName} 被调用`);
                            logNetwork("OBJECT", `对象地址: ${this.toString()}`);
                            
                            if (args.length > 0) {
                                logNetwork("PARAMS", `参数: ${args.map(arg => arg ? arg.toString() : 'null').join(', ')}`);
                            }
                            
                            // 调用原方法
                            const result = NetworkEntityClass[methodName].apply(this, arguments);
                            
                            // 记录返回值
                            if (result !== undefined) {
                                logNetwork("RETURN", `返回值: ${result.toString()}`);
                            }
                            
                            return result;
                        } catch (e) {
                            logNetwork("ERROR", `方法 ${methodName} hook错误: ${e.message}`);
                            return NetworkEntityClass[methodName].apply(this, arguments);
                        }
                    };
                    
                    logNetwork("HOOK", `成功hook方法: ${methodName}`);
                }
            } catch (e) {
                logNetwork("ERROR", `Hook方法 ${methodName} 失败: ${e.message}`);
            }
        });
        
        // Hook 所有字段访问
        const fields = NetworkEntityClass.class.getDeclaredFields();
        fields.forEach(field => {
            const fieldName = field.getName();
            
            try {
                // Hook getter方法
                const getterName = `get${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)}`;
                if (NetworkEntityClass[getterName]) {
                    NetworkEntityClass[getterName].implementation = function() {
                        try {
                            const result = NetworkEntityClass[getterName].apply(this, arguments);
                            logNetwork("GETTER", `NetworkEntity.${getterName} = ${result ? result.toString() : 'null'}`);
                            return result;
                        } catch (e) {
                            logNetwork("ERROR", `Getter ${getterName} hook错误: ${e.message}`);
                            return NetworkEntityClass[getterName].apply(this, arguments);
                        }
                    };
                }
                
                // Hook setter方法
                const setterName = `set${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)}`;
                if (NetworkEntityClass[setterName]) {
                    NetworkEntityClass[setterName].implementation = function(value) {
                        try {
                            logNetwork("SETTER", `NetworkEntity.${setterName} = ${value ? value.toString() : 'null'}`);
                            return NetworkEntityClass[setterName].apply(this, arguments);
                        } catch (e) {
                            logNetwork("ERROR", `Setter ${setterName} hook错误: ${e.message}`);
                            return NetworkEntityClass[setterName].apply(this, arguments);
                        }
                    };
                }
            } catch (e) {
                logNetwork("ERROR", `Hook字段 ${fieldName} 失败: ${e.message}`);
            }
        });
        
    } catch (e) {
        logNetwork("ERROR", `NetworkEntity类hook失败: ${e.message}`);
        logNetwork("INFO", "尝试查找可能的类名变体...");
        
        // 尝试一些可能的类名变体
        const possibleNames = [
            "vn.tpb.dao.entities.NetworkEntity",
            "vn.tpb.dao.entities.NetworkEntityKt",
            "vn.tpb.dao.entities.NetworkEntity$Companion",
            "vn.tpb.dao.entities.NetworkEntity$Builder"
        ];
        
        possibleNames.forEach(name => {
            try {
                const clazz = Java.use(name);
                logNetwork("FOUND", `找到可能的类: ${name}`);
            } catch (e) {
                // 忽略错误
            }
        });
    }
}

// 监控调用NetworkEntity的类
function hookNetworkEntityCallers() {
    logNetwork("INFO", "开始hook可能调用NetworkEntity的类...");
    
    // Hook一些可能调用NetworkEntity的常见类
    const possibleCallers = [
        "vn.tpb.dao.NetworkDao",
        "vn.tpb.dao.DatabaseHelper", 
        "vn.tpb.network.NetworkManager",
        "vn.tpb.network.NetworkService",
        "vn.tpb.repository.NetworkRepository"
    ];
    
    possibleCallers.forEach(className => {
        try {
            const clazz = Java.use(className);
            logNetwork("FOUND", `找到调用者类: ${className}`);
            
            // Hook这个类的所有方法
            const methods = clazz.class.getDeclaredMethods();
            methods.forEach(method => {
                const methodName = method.getName();
                try {
                    if (clazz[methodName]) {
                        clazz[methodName].implementation = function() {
                            try {
                                logNetwork("CALLER", `${className}.${methodName} 被调用`);
                                const result = clazz[methodName].apply(this, arguments);
                                return result;
                            } catch (e) {
                                return clazz[methodName].apply(this, arguments);
                            }
                        };
                    }
                } catch (e) {
                    // 忽略错误
                }
            });
        } catch (e) {
            // 类不存在，忽略
        }
    });
}

// 主函数
function main() {
    logNetwork("INFO", "NetworkEntity 类监控脚本初始化...");
    
    // 延迟执行，确保应用完全加载
    setTimeout(function() {
        hookNetworkEntity();
        hookNetworkEntityCallers();
        
        logNetwork("INFO", "所有hook设置完成，开始监听NetworkEntity类...");
        logNetwork("INFO", "监控目标: vn.tpb.dao.entities.NetworkEntity");
    }, 2000);
}

// 启动脚本
main(); 