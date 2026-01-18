Java.perform(function() {
    console.log("\n[***] 启动 KeyStore 定点清除脚本 [***]");

    var KeyStore = Java.use("java.security.KeyStore");
    var TARGET_ALIAS = "APP_PGB_2"; // 这是你之前抓到的顽固 Key 名字

    try {
        // 1. 获取 AndroidKeyStore 实例
        var ks = KeyStore.getInstance("AndroidKeyStore");
        
        // 2. 加载 KeyStore (AndroidKeyStore 不需要密码，必须传 null)
        ks.load(null);

        // 3. 检查是否存在
        if (ks.containsAlias(TARGET_ALIAS)) {
            console.log("[!] 发现目标密钥: " + TARGET_ALIAS);
            
            // 4. 执行标准 API 删除
            // 这相当于 App 自己调用了 deleteEntry，是合法的，不会崩
            ks.deleteEntry(TARGET_ALIAS);
            
            console.log("[✔] 密钥已成功删除！");
            console.log("    -> App 下次用到它时，会发现不存在，并自动生成新的。");
        } else {
            console.log("[-] 未发现密钥 (已经被删除了，或者别名不对)");
            
            // 为了保险，打印一下当前都有哪些 Key，防止别名变了
            var aliases = ks.aliases();
            console.log("[-] 当前 KeyStore 里存在的别名:");
            while (aliases.hasMoreElements()) {
                console.log("    * " + aliases.nextElement());
            }
        }
        
    } catch (e) {
        console.log("[x] 操作异常: " + e);
    }
});