console.log("[*] 开始列举iOS应用程序包名...");

var LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;
var workspace = LSApplicationWorkspace.defaultWorkspace();
var apps = workspace.allApplications();

console.log("[+] 找到 " + apps.count() + " 个应用程序");

for (var i = 0; i < apps.count(); i++) {
    var app = apps.objectAtIndex_(i);
    var bundleId = app.bundleIdentifier().toString();
    var appName = app.localizedName() ? app.localizedName().toString() : "未知";
    console.log("[+] " + appName + " (" + bundleId + ")");
}

console.log("[*] 列举完成");