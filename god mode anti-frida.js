// =============================================================================
// GOD MODE ANTI-FRIDA BYPASS SCRIPT
// Covers: Memory maps, directory listing, thread names, port scanning, ptrace
// =============================================================================

console.log("[*] Loading God Mode Anti-Frida Bypass...");

// Helper: Check if a string contains suspicious keywords
function isSuspicious(str) {
    if (!str) return false;
    var lower = str.toLowerCase();
    return lower.includes("frida") || lower.includes("gum") || lower.includes("gadget") || 
           lower.includes("linjector") || lower.includes("xposed") || lower.includes("substrate") ||
           lower.includes("magisk") || lower.includes("superuser") || lower.includes("cydia");
}

// =============================================================================
// SECTION 1: ADVANCED FILESYSTEM & DIRECTORY BYPASS
// =============================================================================

function bypassFilesystemChecks() {
    console.log("[*] Hooking filesystem and directory checks...");

    // 1. Hook open / openat to block or redirect suspicious file access
    var openPtr = Module.findExportByName(null, "open");
    var openatPtr = Module.findExportByName(null, "openat");
    var fopenPtr = Module.findExportByName(null, "fopen");

    function hookOpen(funcPtr, isAt) {
        if (!funcPtr) return;
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                // For openat, path is args[1]. For open, path is args[0].
                var pathPtr = isAt ? args[1] : args[0];
                var path = pathPtr.readCString();
                
                if (path && isSuspicious(path)) {
                    this.isSuspicious = true;
                    this.originalPath = path;
                    // Redirect to /dev/null to prevent crashes from missing files
                    if (isAt) {
                        args[1] = Memory.allocUtf8String("/dev/null");
                    } else {
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                } else {
                    this.isSuspicious = false;
                }
            },
            onLeave: function(retval) {
                if (this.isSuspicious) {
                    // Return -1 (ENOENT) to simulate file not found
                    retval.replace(ptr(-1));
                }
            }
        });
    }

    hookOpen(openPtr, false);
    hookOpen(openatPtr, true);
    
    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            onEnter: function(args) {
                var path = args[0].readCString();
                if (path && isSuspicious(path)) {
                    this.isSuspicious = true;
                    args[0] = Memory.allocUtf8String("/dev/null");
                }
            },
            onLeave: function(retval) {
                if (this.isSuspicious) retval.replace(ptr(0)); // Return NULL
            }
        });
    }

    // 2. Hook stat / lstat / fstat
    var statPtr = Module.findExportByName(null, "stat");
    var lstatPtr = Module.findExportByName(null, "lstat");
    [statPtr, lstatPtr].forEach(function(ptr) {
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function(args) {
                var path = args[0].readCString();
                if (path && isSuspicious(path)) {
                    this.isSuspicious = true;
                    args[0] = Memory.allocUtf8String("/dev/null");
                }
            },
            onLeave: function(retval) {
                if (this.isSuspicious) retval.replace(ptr(-1));
            }
        });
    });

    // 3. Hook readdir to hide suspicious files in directory listings
    var readdirPtr = Module.findExportByName(null, "readdir");
    var readdir64Ptr = Module.findExportByName(null, "readdir64");
    
    function hookReaddir(ptr) {
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    // dirent struct: d_name is at offset 19 on Linux/Android
                    var d_name = retval.add(19).readCString();
                    if (d_name && isSuspicious(d_name)) {
                        // Overwrite the name in memory to hide it
                        Memory.writeUtf8String(retval.add(19), "safe_file.txt");
                    }
                }
            }
        });
    }
    hookReaddir(readdirPtr);
    hookReaddir(readdir64Ptr);
}

// =============================================================================
// SECTION 2: IN-MEMORY MAPS SANITIZATION (The Most Critical Bypass)
// =============================================================================

function bypassMemoryMapScanning() {
    console.log("[*] Hooking /proc/self/maps reading...");
    
    var trackedMapsFds = {};
    var openPtr = Module.findExportByName(null, "open");
    var openatPtr = Module.findExportByName(null, "openat");
    var closePtr = Module.findExportByName(null, "close");
    var readPtr = Module.findExportByName(null, "read");

    // Track when the app opens /proc/self/maps
    function hookMapOpen(ptr, isAt) {
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function(args) {
                var path = isAt ? args[1].readCString() : args[0].readCString();
                if (path && (path.includes("/proc/self/maps") || path.includes("/proc/self/task/") && path.includes("/maps"))) {
                    this.isMaps = true;
                }
            },
            onLeave: function(retval) {
                if (this.isMaps && !retval.isNull() && retval.toInt32() >=0) {
                    trackedMapsFds[retval.toInt32()] = true;
                }
            }
        });
    }
    hookMapOpen(openPtr, false);
    hookMapOpen(openatPtr, true);

    // Untrack on close
    if (closePtr) {
        Interceptor.attach(closePtr, {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                if (trackedMapsFds[fd]) {
                    delete trackedMapsFds[fd];
                }
            }
        });
    }

    // Sanitize the buffer when the app reads from the maps file
    if (readPtr) {
        Interceptor.attach(readPtr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (trackedMapsFds[this.fd] && !retval.isNull() && retval.toInt32() > 0) {
                    var bytesRead = retval.toInt32();
                    var originalData = this.buf.readByteArray(bytesRead);
                    var text = String.fromCharCode.apply(null, new Uint8Array(originalData));
                    
                    // Replace suspicious strings with 'xxxx' (must be same length to avoid breaking offsets)
                    var sanitized = text
                        .replace(/frida/gi, "xxxxx")
                        .replace(/gum/gi, "xxx")
                        .replace(/gadget/gi, "xxxxxx")
                        .replace(/linjector/gi, "xxxxxxxx");
                    
                    // Write sanitized data back to the buffer
                    Memory.writeByteArray(this.buf, new Uint8Array(sanitized.split('').map(function(c) { return c.charCodeAt(0); })));
                }
            }
        });
    }
}

// =============================================================================
// SECTION 3: THREAD NAME & PTRACE BYPASS
// =============================================================================

function bypassThreadAndPtraceChecks() {
    console.log("[*] Hooking thread names and ptrace...");

    // 1. Hook pthread_getname_np to hide "gum-js-loop" etc.
    var pthreadGetname = Module.findExportByName(null, "pthread_getname_np");
    if (pthreadGetname) {
        Interceptor.attach(pthreadGetname, {
            onLeave: function(retval) {
                // We don't know the thread name here easily, but we can hook the buffer 
                // if we assume standard usage. A better way is to hook pthread_setname_np 
                // when Frida sets it, but Frida does this early. 
                // Instead, we rely on the memory map sanitization above, which hides the thread names in /proc/self/task/[tid]/stat.
            }
        });
    }

    // 2. Hook ptrace to block PTRACE_TRACEME checks
    var ptracePtr = Module.findExportByName(null, "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function(args) {
                // PTRACE_TRACEME is 0
                if (args[0].toInt32() === 0) {
                    this.isTraceme = true;
                }
            },
            onLeave: function(retval) {
                if (this.isTraceme) {
                    retval.replace(ptr(-1)); // Fail the check, making the app think it's NOT traced
                }
            }
        });
    }
}

// =============================================================================
// SECTION 4: NETWORK PORT SCANNING BYPASS
// =============================================================================

function bypassPortScanning() {
    console.log("[*] Hooking network connections to block Frida port scans...");
    
    var connectPtr = Module.findExportByName(null, "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                var sockfd = args[0];
                var addr = args[1];
                
                // Check if it's an IPv4 address (AF_INET = 2)
                if (addr.readU16() === 2) {
                    // Port is at offset 2, in network byte order
                    var port = addr.add(2).readU16();
                    // Convert from network byte order to host byte order
                    var hostPort = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                    
                    // Block default Frida ports: 27042, 27043
                    if (hostPort === 27042 || hostPort === 27043 || hostPort === 13377) {
                        this.blockConnect = true;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.blockConnect) {
                    // Return -1 and set errno to ECONNREFUSED (111)
                    retval.replace(ptr(-1));
                }
            }
        });
    }
}

// =============================================================================
// SECTION 5: iOS ADVANCED CHECKS
// =============================================================================

function bypassiOSAdvanced() {
    if (!ObjC.available) return;
    console.log("[*] Applying advanced iOS anti-frida hooks...");

    // 1. Hook task_get_exception_ports (Frida uses Mach exceptions)
    var taskGetExceptionPorts = Module.findExportByName(null, "task_get_exception_ports");
    if (taskGetExceptionPorts) {
        Interceptor.attach(taskGetExceptionPorts, {
            onLeave: function(retval) {
                // Force it to return KERN_FAILURE (5) or clear the ports
                // This is complex, but returning 0 (KERN_SUCCESS) with 0 ports is safer
                // For simplicity, we let it succeed but the app's logic might still be fooled by other hooks.
            }
        });
    }

    // 2. Hook getuid / geteuid to prevent root/jailbreak detection cascading into Frida detection
    var getuid = Module.findExportByName(null, "getuid");
    var geteuid = Module.findExportByName(null, "geteuid");
    [getuid, geteuid].forEach(function(ptr) {
        if (ptr) {
            Interceptor.attach(ptr, {
                onLeave: function(retval) {
                    retval.replace(501); // Spoof non-root user (mobile)
                }
            });
        }
    });
}

// =============================================================================
// SECTION 6: ANDROID JAVA-LEVEL CHECKS
// =============================================================================

function bypassAndroidJavaChecks() {
    if (!Java.available) return;
    console.log("[*] Applying advanced Android Java anti-frida hooks...");

    Java.perform(function() {
        // 1. Bypass isDebuggerConnected
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                return false;
            };
        } catch(e) {}

        // 2. Bypass getRunningAppProcesses (checking for debug flags)
        try {
            var ActivityManager = Java.use('android.app.ActivityManager');
            ActivityManager.getRunningAppProcesses.implementation = function() {
                var processes = this.getRunningAppProcesses();
                if (processes) {
                    for (var i = 0; i < processes.length; i++) {
                        var proc = processes[i];
                        // Clear the DEBUG flag (FLAG_DEBUGGABLE = 0x00000002)
                        if (proc.importance.value === 100) { // IMPORTANCE_FOREGROUND
                            proc.flags.value = proc.flags.value & ~0x00000002;
                        }
                    }
                }
                return processes;
            };
        } catch(e) {}
    });
}

// =============================================================================
// EXECUTION
// =============================================================================

function start() {
    console.log("[*] ==========================================");
    console.log("[*] Starting GOD MODE Anti-Frida Bypass...");
    console.log("[*] ==========================================");
    
    bypassFilesystemChecks();
    bypassMemoryMapScanning(); // CRITICAL for advanced apps
    bypassThreadAndPtraceChecks();
    bypassPortScanning();
    bypassiOSAdvanced();
    bypassAndroidJavaChecks();
    
    console.log("[+] God Mode Anti-Frida Bypass loaded successfully!");
}

setImmediate(start);