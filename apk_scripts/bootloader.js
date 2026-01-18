// 记录 fd 到路径的映射
var fd_path_map = {};

function isBootloaderPath(path) {
    if (!path) return false;
    return (
        path.indexOf("/proc/cmdline") === 0 ||
        path.indexOf("/dev/block/by-name/frp") === 0 ||
        path.indexOf("/proc/self/mountinfo") === 0 ||
        path.indexOf("/proc/mounts") === 0
    );
}

// hook open/openat
['open', 'openat'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                console.log("[open] path:", this.path);
            },
            onLeave: function(retval) {
                if (isBootloaderPath(this.path)) {
                    fd_path_map[retval.toInt32()] = this.path;
                    console.log("[open] mapped fd", retval.toInt32(), "to", this.path);
                }
            }
        });
    }
});

// hook fopen/fopen64
['fopen', 'fopen64'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                // FILE* 不能直接映射，略过
            }
        });
    }
});

// hook read/pread/pread64
['read', 'pread', 'pread64'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.nbyte = args[2].toInt32();
            },
            onLeave: function(retval) {
                var path = fd_path_map[this.fd];
                if (path) {
                    console.log("[" + name + "] fd:", this.fd, "path:", path);
                }
                if (path === "/proc/cmdline") {
                    var fake = "androidboot.verifiedbootstate=green androidboot.vbmeta.device_state=locked ...";
                    Memory.writeUtf8String(this.buf, fake);
                    retval.replace(fake.length);
                    console.log("[read] fake /proc/cmdline");
                }
                if (path === "/proc/self/cmdline") {
                    var fake_self = "io.github.vvb2060.keyattestation\0";
                    Memory.writeUtf8String(this.buf, fake_self);
                    retval.replace(fake_self.length);
                    console.log("[read] fake /proc/self/cmdline");
                }
                if (path && path.indexOf("/dev/block/by-name/frp") === 0) {
                    var fake_frp = "\x00".repeat(this.nbyte);
                    Memory.writeByteArray(this.buf, fake_frp);
                    retval.replace(this.nbyte);
                    console.log("[read] fake frp");
                }
                if (path === "/proc/self/mountinfo" || path === "/proc/mounts") {
                    var fake_mount = "";
                    Memory.writeUtf8String(this.buf, fake_mount);
                    retval.replace(fake_mount.length);
                    console.log("[read] fake mountinfo/mounts");
                }
            }
        });
    }
});

// hook fgets/fread
['fgets', 'fread'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.buf = args[0];
            },
            onLeave: function(retval) {
                // 可根据需要伪造内容
            }
        });
    }
});

// hook __system_property_get
Interceptor.attach(Module.findExportByName(null, "__system_property_get"), {
    onEnter: function(args) {
        this.key = Memory.readUtf8String(args[0]);
        this.value_ptr = args[1];
    },
    onLeave: function(retval) {
        if (this.key === "ro.boot.verifiedbootstate") {
            Memory.writeUtf8String(this.value_ptr, "green");
            console.log("[__system_property_get] fake ro.boot.verifiedbootstate");
            return 5;
        }
        if (this.key === "ro.boot.vbmeta.device_state") {
            Memory.writeUtf8String(this.value_ptr, "locked");
            console.log("[__system_property_get] fake ro.boot.vbmeta.device_state");
            return 6;
        }
        if (this.key === "ro.boot.flash.locked") {
            Memory.writeUtf8String(this.value_ptr, "1");
            console.log("[__system_property_get] fake ro.boot.flash.locked");
            return 1;
        }
        if (this.key === "ro.boot.veritymode") {
            Memory.writeUtf8String(this.value_ptr, "enforcing");
            console.log("[__system_property_get] fake ro.boot.veritymode");
            return 9;
        }
        if (this.key === "ro.oem_unlock_supported") {
            Memory.writeUtf8String(this.value_ptr, "0");
            console.log("[__system_property_get] fake ro.oem_unlock_supported");
            return 1;
        }
        if (this.key === "ro.bootloader") {
            Memory.writeUtf8String(this.value_ptr, "locked");
            console.log("[__system_property_get] fake ro.bootloader");
            return 6;
        }
        return retval;
    }
});

// hook access/stat/fstatat
['access', 'stat', 'fstatat'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    this.path = Memory.readUtf8String(args[0]);
                    if (isBootloaderPath(this.path)) {
                        // 可根据需要直接返回-1或伪造
                    }
                } catch (e) {
                    // 忽略非字符串参数
                }
            },
            onLeave: function(retval) {
                // 可根据需要直接返回-1
            }
        });
    }
});

// 不要对 lseek/lseek64/fstat 直接读 args[0] 为字符串
['lseek', 'lseek64', 'fstat'].forEach(function(name) {
    var addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                // 这些函数的第一个参数是 fd 或结构体指针，不要 Memory.readUtf8String
            },
            onLeave: function(retval) {
                // 可根据需要直接返回-1
            }
        });
    }
});

// hook mmap（进阶，部分App用mmap读取分区）
var mmap_addr = Module.findExportByName(null, "mmap");
if (mmap_addr) {
    Interceptor.attach(mmap_addr, {
        onEnter: function(args) {
            // 可记录映射的fd
        },
        onLeave: function(retval) {
            // 可伪造内存内容
        }
    });
}