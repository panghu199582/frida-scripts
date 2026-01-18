// 1. 伪装 __system_property_get
Interceptor.attach(Module.findExportByName(null, "__system_property_get"), {
    onEnter: function(args) {
        this.key = Memory.readUtf8String(args[0]);
        this.value_ptr = args[1];
    },
    onLeave: function(retval) {
        // 伪装常见检测属性
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
        if (this.key === "ro.build.selinux") {
            Memory.writeUtf8String(this.value_ptr, "enforcing");
            return 9;
        }
        return retval;
    }
});

// 2. 伪装 /proc/cmdline
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

// 3. 伪装 open 访问 /dev/tee* /sys/class/tee* /proc/tz*
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path && (path.indexOf("/dev/tee") === 0 || path.indexOf("/proc/tz") === 0 || path.indexOf("/sys/class/tee") === 0)) {
            this.should_fake = true;
        }
    },
    onLeave: function(retval) {
        if (this.should_fake) {
            retval.replace(-1); // open失败
        }
    }
});

// 4. 伪装 su/magisk/xposed/frida 进程/文件检测（可选，进阶）
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        if (path && (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1 || path.indexOf("frida") !== -1 || path.indexOf("xposed") !== -1)) {
            this.should_fake = true;
        }
    },
    onLeave: function(retval) {
        if (this.should_fake) {
            retval.replace(-1); // 文件不存在
        }
    }
});