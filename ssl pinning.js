// =============================================================================
// ULTIMATE ALL-IN-ONE SSL, PROXY, & CERTIFICATE DETECTION BYPASS SCRIPT
// Covers: OpenSSL, BoringSSL, iOS Security, Android Java/OkHttp, Flutter/Dart VM
// Features: Proxy Detection Evasion, Custom CA Certificate Hiding
// =============================================================================

console.log("[*] Loading Ultimate All-in-One Bypass Script...");

// =============================================================================
// SECTION 1: UNIVERSAL NATIVE HOOKS (OpenSSL & BoringSSL)
// =============================================================================

function hookUniversalSSL() {
    // 1. Standard OpenSSL: Force SSL_VERIFY_NONE
    var sslVerifyFuncs = ["SSL_CTX_set_verify", "SSL_set_verify"];
    sslVerifyFuncs.forEach(function(funcName) {
        var func = Module.findExportByName(null, funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    args[1] = ptr(0); // 0 = SSL_VERIFY_NONE
                }
            });
            console.log("[+] Hooked " + funcName);
        }
    });

    // 2. OpenSSL: Force verify result to OK
    var getResult = Module.findExportByName(null, "SSL_get_verify_result");
    if (getResult) {
        Interceptor.attach(getResult, {
            onLeave: function(retval) {
                retval.replace(0); // 0 = X509_V_OK
            }
        });
        console.log("[+] Hooked SSL_get_verify_result");
    }

    // 3. BoringSSL (Used by Android, Flutter, Cronet): Hook custom verify callback
    var symbols = Module.enumerateSymbols(null);
    var customVerifyFound = false;
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name.indexOf("SSL_CTX_set_custom_verify") !== -1 || 
            symbols[i].name.indexOf("SSL_set_custom_verify") !== -1) {
            
            Interceptor.attach(symbols[i].address, {
                onEnter: function(args) {
                    // args[2] is the callback: int (*callback)(SSL *ssl, uint8_t *out_alert)
                    var dummyCallback = new NativeCallback(function(ssl, out_alert) {
                        return 0; // ssl_verify_ok
                    }, 'int', ['pointer', 'pointer']);
                    args[2] = dummyCallback;
                }
            });
            customVerifyFound = true;
        }
    }
    if (customVerifyFound) {
        console.log("[+] Hooked BoringSSL SSL_*_set_custom_verify");
    }
}

// =============================================================================
// SECTION 2: FLUTTER / DART VM SPECIFIC HOOKS
// =============================================================================

function hookFlutterDartVM() {
    var libflutter = Process.findModuleByName("libflutter.so") || Process.findModuleByName("Flutter");
    if (!libflutter) return;

    console.log("[*] Scanning Flutter/Dart VM for native TLS methods...");
    var exports = Module.enumerateExports(libflutter.name);
    
    exports.forEach(function(exp) {
        var name = exp.name;
        
        // Hook Dart's native SecureSocket / BadCertificate evaluators
        if (name.indexOf("SecureSocket") !== -1 || name.indexOf("SecureFilter") !== -1) {
            if (name.indexOf("Handshake") !== -1 || name.indexOf("Connect") !== -1 || name.indexOf("BadCertificate") !== -1 || name.indexOf("VerifyCallback") !== -1) {
                Interceptor.attach(exp.address, {
                    onLeave: function(retval) {
                        retval.replace(0); // Force success / no error
                    }
                });
            }
        }
    });
    console.log("[+] Flutter/Dart VM native hooks applied.");
}

// =============================================================================
// SECTION 3: iOS-SPECIFIC HOOKS (Security, CFNetwork, Proxy, Cert Detection)
// =============================================================================

function hookiOS() {
    if (!ObjC.available) return;
    console.log("[*] Applying iOS-specific hooks...");

    // 1. SecTrustEvaluate (Legacy)
    var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.attach(SecTrustEvaluate, {
            onLeave: function(retval) { retval.replace(0); } // errSecSuccess
        });
    }

    // 2. SecTrustEvaluateWithError (Modern)
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.attach(SecTrustEvaluateWithError, {
            onLeave: function(retval) { retval.replace(1); } // true (Valid)
        });
    }

    // 3. SecTrustSetAnchorCertificatesOnly (Prevent app from restricting to custom certs)
    var SecTrustSetAnchorCertificatesOnly = Module.findExportByName("Security", "SecTrustSetAnchorCertificatesOnly");
    if (SecTrustSetAnchorCertificatesOnly) {
        Interceptor.attach(SecTrustSetAnchorCertificatesOnly, {
            onEnter: function(args) {
                args[1] = ptr(0); // false (Allow system anchors)
            }
        });
    }

    // 4. BYPASS PROXY DETECTION (iOS)
    // CFNetworkCopySystemProxySettings
    var copyProxySettings = Module.findExportByName("CFNetwork", "CFNetworkCopySystemProxySettings");
    if (copyProxySettings) {
        Interceptor.attach(copyProxySettings, {
            onLeave: function(retval) {
                // Return an empty dictionary (no proxy settings)
                var emptyDict = ObjC.classes.NSMutableDictionary.dictionary();
                retval.replace(emptyDict);
            }
        });
        console.log("[+] Bypassed iOS CFNetworkCopySystemProxySettings");
    }

    // CFNetworkCopyProxiesForURL
    var copyProxiesForURL = Module.findExportByName("CFNetwork", "CFNetworkCopyProxiesForURL");
    if (copyProxiesForURL) {
        Interceptor.attach(copyProxiesForURL, {
            onLeave: function(retval) {
                // Return array with kCFProxyTypeNone
                var noProxy = ObjC.classes.NSMutableArray.array();
                noProxy.addObject(ObjC.classes.__NSCFString.stringWithString_("kCFProxyTypeNone"));
                retval.replace(noProxy);
            }
        });
        console.log("[+] Bypassed iOS CFNetworkCopyProxiesForURL");
    }

    // 5. BYPASS CUSTOM CERTIFICATE DETECTION (iOS)
    // Sanitize certificate summaries so apps can't detect "Charles", "Burp", etc.
    var SecCertificateCopySubjectSummary = Module.findExportByName("Security", "SecCertificateCopySubjectSummary");
    var SecCertificateCopyIssuerSummary = Module.findExportByName("Security", "SecCertificateCopyIssuerSummary");
    
    [SecCertificateCopySubjectSummary, SecCertificateCopyIssuerSummary].forEach(function(func) {
        if (func) {
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var str = new ObjC.Object(retval).toString();
                        var lowerStr = str.toLowerCase();
                        if (lowerStr.includes("charles") || lowerStr.includes("fiddler") || 
                            lowerStr.includes("burp") || lowerStr.includes("mitm") || lowerStr.includes("proxy")) {
                            console.log("[*] Sanitized iOS cert detection: " + str);
                            var fakeStr = ObjC.classes.NSString.stringWithString_("CN=Google Trust Services");
                            retval.replace(fakeStr);
                        }
                   
                    }
                }
            });
        }
    });
}

// =============================================================================
// SECTION 4: ANDROID-SPECIFIC HOOKS (Java, Proxy, Cert Detection)
// =============================================================================

function hookAndroid() {
    if (!Java.available) return;
    console.log("[*] Applying Android-specific hooks...");

    Java.perform(function() {
        try {
            // 1. BYPASS TRUST MANAGER (Accept all certs)
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            var TrustManagerImpl = Java.registerClass({
                name: 'com.frida.TrustManagerImpl',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
            
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
                this.init(keyManager, [TrustManagerImpl.$new()], secureRandom);
            };
            console.log("[+] Bypassed Android X509TrustManager");
        } catch(e) { console.log("[-] TrustManager hook failed: " + e); }

        try {
            // 2. BYPASS OKHTTP CERTIFICATE PINNER
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                // Do nothing, bypass pin check
            };
            console.log("[+] Bypassed OkHttp CertificatePinner");
        } catch(e) { /* OkHttp not present */ }

        try {
            // 3. BYPASS WEBVIEW SSL ERRORS
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                handler.proceed(); // Ignore SSL errors
            };
            console.log("[+] Bypassed WebViewClient.onReceivedSslError");
        } catch(e) { /* WebView not present */ }

        // 4. BYPASS PROXY DETECTION (Android)
        try {
            var System = Java.use('java.lang.System');
            System.getProperty.overload('java.lang.String').implementation = function(key) {
                if (key === "http.proxyHost" || key === "https.proxyHost" || key === "http.proxyPort" || key === "https.proxyPort") {
                    return null; // Hide proxy settings
                }
                return this.getProperty(key);
            };
            console.log("[+] Bypassed Android System.getProperty proxy checks");
        } catch(e) {}

        try {
            var ProxySelector = Java.use('java.net.ProxySelector');
            ProxySelector.getDefault().select.overload('java.net.URI').implementation = function(uri) {
                var Proxy = Java.use('java.net.Proxy');
                var ProxyType = Java.use('java.net.Proxy$Type');
                // Return Proxy.NO_PROXY
                return Java.array('java.net.Proxy', [Proxy.$new(ProxyType.NO_PROXY.value, null)]);
            };
            console.log("[+] Bypassed Android ProxySelector checks");
\n        } catch(e) {}

        // 5. BYPASS CUSTOM CERTIFICATE DETECTION (Android)
        // Apps often iterate KeyStore aliases looking for "charles", "fiddler", "burp", "mitm"
        try {
            var KeyStore = Java.use('java.security.KeyStore');
            KeyStore.aliases.overload().implementation = function() {
                var originalAliases = this.aliases();
                var ArrayList = Java.use('java.util.ArrayList');
                var cleanAliases = ArrayList.$new();
                
                var originalEnum = originalAliases.asIterator();
                while (originalEnum.hasNext()) {
                    var alias = originalEnum.next().toString().toLowerCase();
                    if (alias.includes("charles") || alias.includes("fiddler") || 
                        alias.includes("burp") || alias.includes("mitm") || alias.includes("proxy")) {
                        console.log("[*] Hidden malicious KeyStore alias: " + alias);
                    } else {
                        cleanAliases.add(originalEnum.next()); // Keep legitimate aliases
                    }
                }
                return cleanAliases;
            };
            console.log("[+] Bypassed Android KeyStore custom cert detection");
        } catch(e) {}

        // Also sanitize X509Certificate issuer/subject names if the app checks them directly
        try {
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            X509Certificate.getIssuerDN.overload().implementation = function() {
                var original = this.getIssuerDN();
                var name = original.getName().toLowerCase();
                if (name.includes("charles") || name.includes("fiddler") || name.includes("burp") || name.includes("mitm")) {
                    console.log("[*] Sanitized Android X509Certificate Issuer DN");
                    var FakePrincipal = Java.registerClass({
                        name: 'com.frida.FakePrincipal',
                        implements: [Java.use('java.security.Principal')],
                        methods: {
                            getName: function() { return "CN=Google Trust Services, O=Google LLC, C=US"; }
                        }
                    });
                    return FakePrincipal.$new();
                }
                return original;
            };
        } catch(e) {}

	// Hook HostnameVerifier
	try {
	    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
	    // Hook the default implementation or common custom ones
	    var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
	    OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(host, session) {
	        console.log("[+] Bypassed HostnameVerifier for: " + host);
	        return true;
	    };
	} catch(e) {}
    });
}

// =============================================================================
// EXECUTION
// =============================================================================

function start() {
    console.log("[*] ==========================================");
    console.log("[*] Starting Ultimate All-in-One Bypass...");
    console.log("[*] ==========================================");
    
    hookUniversalSSL();
    hookFlutterDartVM();
    hookiOS();
    hookAndroid();
    
    console.log("[+] Ultimate Bypass Script loaded successfully!");
    console.log("[*] Ready to intercept traffic.");
}

setImmediate(start);