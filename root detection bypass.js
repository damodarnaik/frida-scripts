// ==========================================
// 1. CONSTANTS & HELPERS
// ==========================================
const ROOT_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", 
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", 
    "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon", 
    "/system/xbin/daemonsu", "/vendor/bin/su", "/cache/su", "/data/su", 
    "/dev/su", "/system/bin/.ext/su", "/system/usr/we-need-root/su", 
    "/system/app/Kinguser.apk", "/data/adb/magisk", "/sbin/.magisk", 
    "/cache/.disable_magisk", "/dev/.magisk.unblock", "/cache/magisk.log", 
    "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple", 
    "/init.magisk.rc", "/system/xbin/ku.sud", "/data/adb/ksu", "/data/adb/ksud",
    "/system/bin/magisk", "/system/xbin/magisk", "/data/local/tmp", "/data/data/com.topjohnwu.magisk"
];

const ROOT_PACKAGES = [
    "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
    "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
    "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro", "com.topjohnwu.magisk", "me.weishu.kernelsu",
    "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer",
    "com.saurik.substrate", "io.github.vvb2060.magisk", "com.kingouser.com", "me.bmax.apatch"
];

const FAKE_PATH = "/system/bin/__frida_fake_path__";
var trackedProcFds = [];

function isRootPath(path) {
    if (!path) return false;
    for (let i = 0; i < ROOT_PATHS.length; i++) {
        if (path.indexOf(ROOT_PATHS[i]) !== -1) return true;
    }
    let lower = path.toLowerCase();
    return lower.includes("magisk") || lower.includes("/su") || lower.includes("superuser") || 
           lower.includes("supersu") || lower.includes("busybox") || lower.includes("xposed") || 
           lower.includes("frida") || lower.includes("gadget") || lower.includes("substrate") ||
           lower.includes("apatch") || lower.includes("ksu");
}

// ==========================================
// 2. NATIVE HOOKS (Syscalls, RASP, Memory, UID)
// ==========================================
function hookNative() {
    console.log("[*] Hooking Advanced Native & RASP Functions...");

    // --- UID/GID SPOOFING (Prevents getuid() == 0 checks) ---
    ["getuid", "geteuid", "getgid", "getegid"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) {
                        console.log("[+] Bypass " + funcName + " (was 0, spoofing to 10234)");
                        retval.replace(10234); // Spoof a normal app UID
                    }
                }
            });
        }
    });

    // --- ENVIRONMENT VARIABLE SPOOFING ---
    let getenv = Module.findExportByName("libc.so", "getenv");
    if (getenv) {
        Interceptor.attach(getenv, {
            onEnter: function(args) {
                this.varName = args[0].readCString();
            },
            onLeave: function(retval) {
                if (this.varName) {
                    let lowerVar = this.varName.toLowerCase();
                    if (lowerVar.includes("frida") || lowerVar.includes("xposed") || 
                        lowerVar.includes("ld_preload") || lowerVar.includes("substrate")) {
                        console.log("[+] Bypass getenv: " + this.varName);
                        retval.replace(ptr(0)); // Return NULL
                    }
                }
            }
        });
    }

    // --- LIBRARY LOADING SPOOFING (dlopen) ---
    ["dlopen", "android_dlopen_ext"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    this.path = args[0].readCString();
                    if (this.path && isRootPath(this.path)) {
                        console.log("[+] Bypass " + funcName + ": " + this.path);
                        args[0].writeUtf8String(FAKE_PATH);
                    }
                }
            });
        }
    });

    // --- FILE OPENING ---
    ["fopen", "open", "openat"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    let argIdx = funcName === "openat" ? 1 : 0;
                    this.path = args[argIdx].readCString();
                    if (isRootPath(this.path)) {
                        console.log("[+] Bypass " + funcName + ": " + this.path);
                        args[argIdx].writeUtf8String(FAKE_PATH);
                    }
                },
                onLeave: function(retval) {
                    let fd = retval.toInt32();
                    let path = this.path || "";
                    if (fd > 0 && (path.includes("/proc/mounts") || path.includes("/proc/self/mounts") || 
                                   path.includes("/proc/self/maps") || path.includes("/proc/self/status") ||
                                   path.includes("/proc/self/cmdline") || path.includes("/proc/self/task/"))) {
                        trackedProcFds.push(fd);
                    }
                }
            });
        }
    });

    // --- FILE EXISTENCE & METADATA (Including 64-bit variants) ---
    ["access", "faccessat", "faccessat2", "stat", "stat64", "lstat", "lstat64", "fstatat", "fstatat64"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    let argIdx = (funcName === "faccessat" || funcName === "faccessat2" || funcName === "fstatat" || funcName === "fstatat64") ? 1 : 0;
                    this.path = args[argIdx].readCString();
                    this.isRoot = isRootPath(this.path);
                },
                onLeave: function(retval) {
                    if (this.isRoot) {
                        console.log("[+] Bypass " + funcName + ": " + this.path);
                        retval.replace(-1);
                    }
                }
            });
        }
    });

    // --- COMMAND EXECUTION ---
    ["system", "popen"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    let cmd = args[0].readCString();
                    if (cmd.includes("getprop") || cmd === "mount" || cmd.includes("build.prop") || cmd === "id" || cmd === "su") {
                        console.log("[+] Bypass native " + funcName + ": " + cmd);
                        args[0].writeUtf8String("grep");
                    }
                }
            });
        }
    });

    ["execve", "execv", "execvp"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    let path = args[0].readCString();
                    if (path === "su" || path.includes("/su") || path.includes("magisk")) {
                        console.log("[+] Bypass native " + funcName + ": " + path);
                        args[0].writeUtf8String(FAKE_PATH);
                    }
                }
            });
        }
    });

    // --- DIRECTORY LISTING ---
    ["readdir", "readdir64"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        let namePtr = retval.add(19); // 64-bit dirent struct offset for name
                        let name = namePtr.readCString();
                        if (name && isRootPath(name)) {
                            console.log("[+] Bypass " + funcName + ": " + name);
                            namePtr.writeUtf8String(".");
                        }
                    }
                }
            });
        }
    });

    // --- ADVANCED RASP: PTRACE, PRCTL, INOTIFY ---
    let ptrace = Module.findExportByName("libc.so", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) { this.request = args[0].toInt32(); },
            onLeave: function(retval) {
                if (this.request === 0) { // PTRACE_TRACEME
                    console.log("[+] Bypass ptrace PTRACE_TRACEME");
                    retval.replace(0);
                }
            }
        });
    }

    let prctl = Module.findExportByName("libc.so", "prctl");
    if (prctl) {
        Interceptor.attach(prctl, {
            onEnter: function(args) { this.option = args[0].toInt32(); },
            onLeave: function(retval) {
                if (this.option === 3) { // PR_GET_DUMPABLE (1 if debuggable, 0 if not)
                    console.log("[+] Bypass prctl PR_GET_DUMPABLE");
                    retval.replace(0); // Fake non-dumpable
                }
            }
        });
    }

    ["inotify_init", "inotify_init1", "inotify_add_watch"].forEach(funcName => {
        let func = Module.findExportByName("libc.so", funcName);
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    console.log("[+] Bypass " + funcName);
                    retval.replace(-1); // Fail silently
                }
            });
        }
    });

    // --- THREAD NAME SPOOFING (Anti-Frida thread detection) ---
    let pthread_getname_np = Module.findExportByName("libc.so", "pthread_getname_np");
    if (pthread_getname_np) {
        Interceptor.attach(pthread_getname_np, {
            onLeave: function(retval) {
                // We can't easily read the thread name here without the args, 
                // but we can hook the Java side or rely on the /proc scrubber below.
            }
        });
    }

    // --- CONTENT FILTERING (Scrubbing /proc files dynamically) ---
    let read = Module.findExportByName("libc.so", "read");
    if (read) {
        Interceptor.attach(read, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave: function(retval) {
                let bytesRead = retval.toInt32();
                if (bytesRead > 0 && trackedProcFds.includes(this.fd)) {
                    try {
                        let content = this.buf.readCString(bytesRead);
                        let originalLen = content.length;
                        
                        // 1. Scrub TracerPid (Anti-debugging)
                        if (content.includes("TracerPid:")) {
                            content = content.replace(/TracerPid:\t\d+/g, "TracerPid:\t0");
                        }
                        
                        // 2. Scrub Thread Names (Anti-Frida)
                        if (content.includes("Name:")) {
                            content = content.replace(/Name:\s+(gmain|gdbus|pool-frida|gum-js-loop)/g, "Name:\tWorker");
                        }

                        // 3. Scrub memory maps and mounts
                        let lines = content.split('\n');
                        let filtered = lines.filter(line => {
                            let l = line.toLowerCase();
                            return !l.includes("frida") && !l.includes("gadget") && !l.includes("magisk") && 
                                   !l.includes("xposed") && !l.includes("substrate") && !l.includes("tmpfs /system") && 
                                   !l.includes("/su ") && !l.includes("supersu") && !l.includes("ksu") &&
                                   !l.includes("apatch");
                        }).join('\n');
                        
                        // Only rewrite if we actually filtered something to save CPU
                        if (filtered.length < originalLen) {
                            let newLen = this.buf.writeUtf8String(filtered);
                            retval.replace(newLen);
                        }
                    } catch (e) { 
                        // Ignore parse errors to prevent app crashes
                    }
                }
            }
        });
    }
}

hookNative();

// ==========================================
// 3. JAVA HOOKS
// ==========================================
Java.perform(function() {
    console.log("[*] Hooking Advanced Java Functions...");

    // --- Java File Checks ---
    try {
        let UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            let filename = file.getAbsolutePath().toString();
            if (isRootPath(filename)) {
                console.log("[+] Bypass Java checkAccess: " + filename);
                return false;
            }
            return this.checkAccess(file, access);
        };
    } catch (e) {}

    try {
        let File = Java.use("java.io.File");
        File.exists.implementation = function() {
            let name = this.getName().toString();
            if (["su", "busybox", "supersu", "superuser.apk", "magisk", "ksu", "apatch"].includes(name.toLowerCase())) {
                console.log("[+] Bypass File.exists: " + name);
                return false;
            }
            return this.exists();
        };

        File.listFiles.overload().implementation = function() {
            let files = this.listFiles();
            if (files) {
                let filtered = [];
                for (let i = 0; i < files.length; i++) {
                    let name = files[i].getName().toString().toLowerCase();
                    if (!name.includes("su") && !name.includes("magisk") && !name.includes("busybox") && 
                        !name.includes("xposed") && !name.includes("frida") && !name.includes("gadget") &&
                        !name.includes("apatch") && !name.includes("ksu")) {
                        filtered.push(files[i]);
                    }
                }
                return Java.array("java.io.File", filtered);
            }
            return files;
        };
    } catch (e) {}

    // --- Java Execution ---
    try {
        let ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
            if (cmdarray && cmdarray.length > 0) {
                let cmd0 = cmdarray[0].toString().toLowerCase();
                if (cmd0 === "mount" || cmd0 === "getprop" || cmd0 === "su" || cmd0.includes("which")) {
                    console.log("[+] Bypass ProcessImpl: " + cmd0);
                    arguments[0] = Java.array('java.lang.String', [""]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }
            return ProcessImpl.start.apply(this, arguments);
        };
    } catch (e) {}

    // --- Java Properties & Build ---
    try {
        let SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload('java.lang.String').implementation = function(name) {
            let nameStr = name.toString();
            let props = { "ro.build.selinux": "1", "ro.debuggable": "0", "service.adb.root": "0", "ro.secure": "1" };
            if (props.hasOwnProperty(nameStr)) {
                console.log("[+] Bypass SystemProperties: " + nameStr);
                return props[nameStr];
            }
            return this.get(name);
        };

        let Build = Java.use("android.os.Build");
        let TAGS = Build.class.getDeclaredField("TAGS");
        TAGS.setAccessible(true);
        TAGS.set(null, "release-keys");

        let FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
        FINGERPRINT.setAccessible(true);
        FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys");
    } catch (e) {}

    // --- Package Manager ---
    try {
        let AppPM = Java.use("android.app.ApplicationPackageManager");
        AppPM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            let strName = str.toString();
            if (ROOT_PACKAGES.indexOf(strName) >= 0) {
                console.log("[+] Bypass PackageManager: " + strName);
                str = Java.use("java.lang.String").$new("ashen.one.ye.not.found");
            }
            return this.getPackageInfo(str, i);
        };
    } catch (e) {}

    // --- Anti-Hooking / ClassLoader ---
    try {
        let Class = Java.use("java.lang.Class");
        Class.forName.overload("java.lang.String").implementation = function(name) {
            let n = name.toString().toLowerCase();
            if (n.includes("xposed") || n.includes("frida") || n.includes("substrate") || n.includes("superuser") || n.includes("gadget")) {
                console.log("[+] Blocked Class.forName: " + n);
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
            }
            return this.forName(name);
        };

        let ClassLoader = Java.use("java.lang.ClassLoader");
        ClassLoader.loadClass.overload("java.lang.String").implementation = function(name) {
            let n = name.toString().toLowerCase();
            if (n.includes("xposed") || n.includes("frida") || n.includes("substrate") || n.includes("superuser") || n.includes("gadget")) {
                console.log("[+] Blocked ClassLoader.loadClass: " + n);
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
            }
            return this.loadClass(name);
        };
    } catch (e) {}

    // --- String Contains (test-keys) ---
    try {
        let StringClass = Java.use('java.lang.String');
        StringClass.contains.implementation = function(name) {
            if (name.toString() === "test-keys") {
                console.log("[+] Bypass test-keys check");
                return false;
            }
            return this.contains(name);
        };
    } catch (e) {}
});

console.log("[*] Maximum Power Root & RASP Bypass Script Loaded Successfully");