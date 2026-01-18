if (Java.available) {
    Java.perform(function() {
        var currentApp = Java.use("android.app.ActivityThread").currentApplication();
        var context = currentApp ? currentApp.getApplicationContext() : null;
        var packageName = context ? context.getPackageName() : "";

        // 只针对 com.scb.phone
        if (packageName === "com.scb.phone") {
            // 1. Hook Settings.Global.getInt
            var SettingsGlobal = Java.use("android.provider.Settings$Global");
            SettingsGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                if (name === "adb_enabled" || name === "development_settings_enabled") {
                    return 0;
                }
                return this.getInt(cr, name);
            };

            // 2. Hook Settings.Secure.getInt
            var SettingsSecure = Java.use("android.provider.Settings$Secure");
            SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                if (name === "adb_enabled") {
                    return 0;
                }
                return this.getInt(cr, name);
            };

            // 3. Hook SystemProperties.get
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                if (key === "ro.debuggable" || key === "persist.sys.usb.config") {
                    return "0";
                }
                if (key === "ro.boot.verifiedbootstate") return "green";
                if (key === "ro.boot.vbmeta.device_state") return "locked";
                if (key === "ro.boot.flash.locked") return "1";
                if (key === "ro.boot.veritymode") return "enforcing";
                if (key === "ro.oem_unlock_supported") return "0";
                if (key === "ro.bootloader") return "locked";
                return this.get(key);
            };
        }
    });
}

// Native hook部分不区分包名，建议只在目标进程注入
var is_cmdline_fd = {};
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        this.is_cmdline = (path === "/proc/cmdline");
    }
});

Interceptor.attach(Module.findExportByName(null, "fgets"), {
    onEnter: function(args) {
        this.buf = args[0];
    },
    onLeave: function(retval) {
        if (this.is_cmdline) {
            var fake = Memory.allocUtf8String("androidboot.verifiedbootstate=green androidboot.vbmeta.device_state=locked ...");
            Memory.writePointer(this.buf, fake);
            return fake;
        }
        return retval;
    }
});

Interceptor.attach(Module.findExportByName(null, "__system_property_get"), {
    onEnter: function(args) {
        this.key = Memory.readUtf8String(args[0]);
        this.value_ptr = args[1];
    },
    onLeave: function(retval) {
        if (this.key === "ro.boot.verifiedbootstate") {
            Memory.writeUtf8String(this.value_ptr, "green");
            return 5;
        }
        if (this.key === "ro.boot.vbmeta.device_state") {
            Memory.writeUtf8String(this.value_ptr, "locked");
            return 6;
        }
        if (this.key === "ro.boot.flash.locked") {
            Memory.writeUtf8String(this.value_ptr, "1");
            return 1;
        }
        if (this.key === "ro.boot.veritymode") {
            Memory.writeUtf8String(this.value_ptr, "enforcing");
            return 9;
        }
        if (this.key === "ro.oem_unlock_supported") {
            Memory.writeUtf8String(this.value_ptr, "0");
            return 1;
        }
        if (this.key === "ro.bootloader") {
            Memory.writeUtf8String(this.value_ptr, "locked");
            return 6;
        }
        return retval;
    }
});

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path && (path.indexOf("/dev/tee") === 0 || path.indexOf("/proc/tz") === 0 || path.indexOf("/sys/class/tee") === 0)) {
            // 你可以让open失败，返回-1
            this.should_fake = true;
        }
    },
    onLeave: function(retval) {
        if (this.should_fake) {
            retval.replace(-1); // open失败
        }
    }
}); 