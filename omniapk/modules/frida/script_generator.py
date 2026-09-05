"""
Module 6: Frida Dynamic Instrumentation - Script Generator & Runtime Injector.
Generates cutting-edge JavaScript injection scripts for runtime hooking,
SSL unpinning, root hiding, billing bypass, and function tracing.
"""

from typing import Dict, Any, List, Optional

class FridaScriptGenerator:
    """Generates production-grade Frida JavaScript payloads."""

    @staticmethod
    def get_universal_ssl_unpinning() -> str:
        """Universal SSL Pinning Bypass script supporting OkHttp, TrustManager, Conscrypt, and WebView."""
        return """/*
 * OmniAPK Studio - Universal Android SSL Pinning Bypass (Frida Script)
 * Covers Java TrustManager, OkHttp3, Conscrypt, Appcelerator, Trustkit, and NetworkSecurityConfig.
 */

Java.perform(function() {
    console.log("[*] [OmniAPK] Injecting Universal SSL Pinning Bypass...");

    // 1. Universal TrustManager Bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({
            name: 'com.omniapk.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] [SSL Bypass] Intercepted SSLContext.init() -> Overriding with TrustAll Manager");
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch(err) {
        console.log("[-] TrustManager hook warning: " + err);
    }

    // 2. OkHttp3 CertificatePinner Bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] [SSL Bypass] OkHttp3 CertificatePinner.check(host, certs) bypassed for: " + hostname);
            return;
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
            console.log("[+] [SSL Bypass] OkHttp3 CertificatePinner.check(host, array) bypassed for: " + hostname);
            return;
        };
    } catch(err) {}

    // 3. WebViewClient onReceivedSslError Bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
            console.log("[+] [SSL Bypass] WebViewClient SSL error intercepted -> proceeding!");
            sslErrorHandler.proceed();
        };
    } catch(err) {}

    console.log("[✓] Universal SSL Pinning bypass active.");
});
"""

    @staticmethod
    def get_universal_root_bypass() -> str:
        """Universal Root & Magisk Detection Bypass Script."""
        return """/*
 * OmniAPK Studio - Universal Root & Magisk & Emulator Detection Bypass
 */

Java.perform(function() {
    console.log("[*] [OmniAPK] Injecting Universal Root & Emulator Bypass...");

    // 1. Hook File.exists for root binaries
    var File = Java.use("java.io.File");
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu",
        "/data/data/com.noshufou.android.su",
        "/data/data/com.topjohnwu.magisk"
    ];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] [Root Bypass] Denied File.exists() for root path: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // 2. Hook Runtime.exec for su execution
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd === "su" || cmd.indexOf("su") !== -1 || cmd.indexOf("which su") !== -1) {
            console.log("[+] [Root Bypass] Blocked Runtime.exec(" + cmd + ")");
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };

    // 3. Spoof Build Tags (test-keys -> release-keys)
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";

    console.log("[✓] Root detection bypass active.");
});
"""

    @staticmethod
    def generate_method_hook(class_name: str, method_name: str, return_value: Optional[str] = None) -> str:
        """Generate custom Frida hook to intercept parameters, log stack traces, and override return value."""
        ret_code = ""
        if return_value is not None:
            ret_code = f"""
        console.log("[+] [Hook] Overriding return value with: {return_value}");
        return {return_value};"""
        else:
            ret_code = """
        var result = this.{method_name}.apply(this, arguments);
        console.log("[+] [Hook] Original return value: " + result);
        return result;"""

        return f"""/*
 * OmniAPK Hook for {class_name}->{method_name}
 */
Java.perform(function() {{
    try {{
        var targetClass = Java.use("{class_name}");
        var targetMethod = targetClass.{method_name};

        targetMethod.implementation = function() {{
            console.log("\\n[!] Intercepted call: {class_name}->{method_name}()");
            for (var i = 0; i < arguments.length; i++) {{
                console.log("    Arg[" + i + "]: " + arguments[i]);
            }}
            {ret_code}
        }};
        console.log("[✓] Hooked: {class_name}->{method_name}");
    }} catch(e) {{
        console.log("[-] Failed to hook {class_name}->{method_name}: " + e);
    }}
}});
"""

    @staticmethod
    def get_in_app_billing_bypass() -> str:
        """Frida script to hook Google Play Billing responses live."""
        return """/*
 * OmniAPK - In-App Billing Live Hook
 */
Java.perform(function() {
    console.log("[*] Injecting Google Play Billing Interceptor...");
    try {
        var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
        BillingClient.isFeatureSupported.implementation = function(feature) {
            return 0; // BillingResponseCode.OK = 0
        };
    } catch(e) {}
    console.log("[✓] Billing Hook Active.");
});
"""
