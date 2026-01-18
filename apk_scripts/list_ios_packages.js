// list_ios_packages.js
console.log("[*] Starting iOS package listing...");

setTimeout(function() {
    try {
        // 使用NSWorkspace获取所有应用程序
        var NSWorkspace = ObjC.classes.NSWorkspace;
        var workspace = NSWorkspace.sharedWorkspace();
        var applications = workspace.runningApplications();
        
        console.log("[+] Running Applications:");
        console.log("----------------------------------------");
        
        var count = applications.count();
        for (var i = 0; i < count; i++) {
            var app = applications.objectAtIndex_(i);
            console.log("Bundle ID: " + app.bundleIdentifier().toString());
            console.log("App Name: " + app.localizedName().toString());
            console.log("----------------------------------------");
        }
        
        // 使用NSFileManager获取所有应用程序
        var NSFileManager = ObjC.classes.NSFileManager;
        var fileManager = NSFileManager.defaultManager();
        
        // 获取应用程序目录
        var NSSearchPathDirectory = ObjC.classes.NSSearchPathDirectory;
        var NSSearchPathDomainMask = ObjC.classes.NSSearchPathDomainMask;
        
        var appDir = NSSearchPathForDirectoriesInDomains_(NSSearchPathDirectory.NSApplicationDirectory, NSSearchPathDomainMask.NSUserDomainMask, true);
        var systemAppDir = NSSearchPathForDirectoriesInDomains_(NSSearchPathDirectory.NSApplicationDirectory, NSSearchPathDomainMask.NSSystemDomainMask, true);
        
        console.log("[+] Installed Applications:");
        console.log("----------------------------------------");
        
        // 用户安装的应用
        var userApps = fileManager.contentsOfDirectoryAtPath_error_(appDir.objectAtIndex_(0), NULL);
        var userAppCount = userApps.count();
        
        console.log("[*] User Applications (" + userAppCount + "):");
        for (var i = 0; i < userAppCount; i++) {
            var appPath = userApps.objectAtIndex_(i);
            var appName = appPath.lastPathComponent().toString();
            console.log(appName);
        }
        
        // 系统应用
        var systemApps = fileManager.contentsOfDirectoryAtPath_error_(systemAppDir.objectAtIndex_(0), NULL);
        var systemAppCount = systemApps.count();
        
        console.log("[*] System Applications (" + systemAppCount + "):");
        for (var i = 0; i < systemAppCount; i++) {
            var appPath = systemApps.objectAtIndex_(i);
            var appName = appPath.lastPathComponent().toString();
            console.log(appName);
        }
        
        // 使用LSApplicationWorkspace获取所有应用程序
        var LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;
        var workspace2 = LSApplicationWorkspace.defaultWorkspace();
        var allApps = workspace2.allApplications();
        
        console.log("[+] All Applications (with Bundle IDs):");
        console.log("----------------------------------------");
        
        var allAppCount = allApps.count();
        for (var i = 0; i < allAppCount; i++) {
            var app = allApps.objectAtIndex_(i);
            var bundleID = app.bundleIdentifier().toString();
            var appName = app.localizedName().toString();
            console.log("Bundle ID: " + bundleID);
            console.log("App Name: " + appName);
            console.log("----------------------------------------");
        }
        
        console.log("[*] Found " + allAppCount + " applications in total");
        
    } catch(e) {
        console.log("[!] Error:", e.message);
    }
}, 1000); 