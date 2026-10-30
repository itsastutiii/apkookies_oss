// Frida hook: Anti-analysis detection
// Monitors emulator checks, debugger checks, Build property checks, suspicious environment checks

Java.perform(function () {
    // Build properties - common emulator detection vectors
    try {
        var Build = Java.use("android.os.Build");
        var fields = [
            "BRAND", "DEVICE", "MODEL", "PRODUCT", "MANUFACTURER",
            "HARDWARE", "FINGERPRINT", "TAGS", "TYPE", "BOARD",
            "BOOTLOADER", "RADIO", "SERIAL", "HOST", "ID"
        ];
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            try {
                var getter = Build[field];
                if (getter && getter.getter) {
                    // This is a static field, hook via class
                }
            } catch (e) {}
        }

        // Hook Build.getSerial() - often checked for "unknown" or emulator serials
        var getSerial = Build.getSerial.overload();
        getSerial.implementation = function () {
            var result = this.getSerial();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Build.getSerial",
                args: {serial: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // Build.VERSION - SDK checks
    try {
        var BuildVersion = Java.use("android.os.Build$VERSION");
        var sdkInt = BuildVersion.SDK_INT;
        // Static field, can't easily hook, but we can hook methods that use it
    } catch (e) {}

    // Debug.isDebuggerConnected()
    try {
        var Debug = Java.use("android.os.Debug");
        var isDebuggerConnected = Debug.isDebuggerConnected.overload();
        isDebuggerConnected.implementation = function () {
            var result = this.isDebuggerConnected();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Debug.isDebuggerConnected",
                args: {result: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var isDebugging = Debug.isDebugging.overload();
        isDebugging.implementation = function () {
            var result = this.isDebugging();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Debug.isDebugging",
                args: {result: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // Debug.getDebuggerConnected() - alternative
    try {
        var getDebuggerConnected = Debug.getDebuggerConnected.overload();
        getDebuggerConnected.implementation = function () {
            var result = this.getDebuggerConnected();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Debug.getDebuggerConnected",
                args: {result: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // Runtime.exec - command execution (often used for root/emulator checks)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var exec = Runtime.exec.overload('java.lang.String');
        exec.implementation = function (cmd) {
            var result = this.exec(cmd);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Runtime.exec(String)",
                args: {command: cmd},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var exec2 = Runtime.exec.overload('[Ljava.lang.String;');
        exec2.implementation = function (cmds) {
            var cmdStr = "";
            for (var i = 0; i < cmds.length; i++) {
                cmdStr += cmds[i] + " ";
            }
            var result = this.exec(cmds);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Runtime.exec(String[])",
                args: {command: cmdStr.trim()},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var exec3 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
        exec3.implementation = function (cmd, env) {
            var result = this.exec(cmd, env);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Runtime.exec(String,String[])",
                args: {command: cmd},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
        exec4.implementation = function (cmds, env) {
            var cmdStr = "";
            for (var i = 0; i < cmds.length; i++) {
                cmdStr += cmds[i] + " ";
            }
            var result = this.exec(cmds, env);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "Runtime.exec(String[],String[])",
                args: {command: cmdStr.trim()},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // ProcessBuilder - another way to execute commands
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        var $init = ProcessBuilder.$init.overload('[Ljava.lang.String;');
        $init.implementation = function (cmds) {
            var cmdStr = "";
            for (var i = 0; i < cmds.length; i++) {
                cmdStr += cmds[i] + " ";
            }
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "ProcessBuilder.<init>",
                args: {command: cmdStr.trim()},
                stack: stack.substring(0, 500)
            });
            return this.$init(cmds);
        };

        var start = ProcessBuilder.start.overload();
        start.implementation = function () {
            var result = this.start();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "ProcessBuilder.start",
                args: {command: this.command ? this.command().toString() : "unknown"},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // File.exists - checking for su, busybox, emulator files
    try {
        var File = Java.use("java.io.File");
        var exists = File.exists.overload();
        exists.implementation = function () {
            var path = this.getAbsolutePath();
            var result = this.exists();
            var suspicious = false;
            var suspiciousPaths = [
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/system/bin/busybox", "/system/xbin/busybox",
                "/dev/qemu_pipe", "/dev/socket/qemud",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/proc/tty/drivers"
            ];
            for (var i = 0; i < suspiciousPaths.length; i++) {
                if (path.indexOf(suspiciousPaths[i]) >= 0) {
                    suspicious = true;
                    break;
                }
            }
            if (suspicious || result) {
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                send({
                    group: "anti_analysis",
                    api: "File.exists",
                    args: {
                        path: path,
                        exists: result,
                        suspicious: suspicious
                    },
                    stack: stack.substring(0, 500)
                });
            }
            return result;
        };
    } catch (e) {}

    // System.getProperty - checking java.vm.name, etc.
    try {
        var System = Java.use("java.lang.System");
        var getProperty = System.getProperty.overload('java.lang.String');
        getProperty.implementation = function (key) {
            var result = this.getProperty(key);
            var suspiciousKeys = [
                "java.vm.name", "java.vm.version", "java.vm.vendor",
                "os.name", "os.arch", "os.version",
                "ro.kernel.qemu", "ro.hardware", "ro.product.model"
            ];
            var isSuspicious = false;
            for (var i = 0; i < suspiciousKeys.length; i++) {
                if (key === suspiciousKeys[i]) {
                    isSuspicious = true;
                    break;
                }
            }
            if (isSuspicious) {
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                send({
                    group: "anti_analysis",
                    api: "System.getProperty",
                    args: {key: key, value: result},
                    stack: stack.substring(0, 500)
                });
            }
            return result;
        };
    } catch (e) {}

    // TelephonyManager - device ID checks (IMEI)
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        var getDeviceId = TelephonyManager.getDeviceId.overload();
        getDeviceId.implementation = function () {
            var result = this.getDeviceId();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "TelephonyManager.getDeviceId",
                args: {deviceId: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var getImei = TelephonyManager.getImei.overload();
        getImei.implementation = function () {
            var result = this.getImei();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "TelephonyManager.getImei",
                args: {imei: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var getSimSerialNumber = TelephonyManager.getSimSerialNumber.overload();
        getSimSerialNumber.implementation = function () {
            var result = this.getSimSerialNumber();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "TelephonyManager.getSimSerialNumber",
                args: {simSerial: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var getSubscriberId = TelephonyManager.getSubscriberId.overload();
        getSubscriberId.implementation = function () {
            var result = this.getSubscriberId();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "TelephonyManager.getSubscriberId",
                args: {subscriberId: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // SensorManager - checking for sensors (emulators often lack them)
    try {
        var SensorManager = Java.use("android.hardware.SensorManager");
        var getSensorList = SensorManager.getSensorList.overload('int');
        getSensorList.implementation = function (type) {
            var result = this.getSensorList(type);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "SensorManager.getSensorList",
                args: {type: type, count: result ? result.size() : 0},
                stack: stack.substring(0, 500)
            });
            return result;
        };

        var getDefaultSensor = SensorManager.getDefaultSensor.overload('int');
        getDefaultSensor.implementation = function (type) {
            var result = this.getDefaultSensor(type);
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "SensorManager.getDefaultSensor",
                args: {type: type, hasSensor: !!result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // PackageManager - checking for installed packages (su, Magisk, etc.)
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        var getPackageInfo = PackageManager.getPackageInfo.overload('java.lang.String', 'int');
        getPackageInfo.implementation = function (pkg, flags) {
            var result = this.getPackageInfo(pkg, flags);
            var suspiciousPackages = [
                "com.topjohnwu.magisk", "eu.chainfire.supersu",
                "com.koushikdutta.superuser", "com.noshufou.android.su"
            ];
            var isSuspicious = false;
            for (var i = 0; i < suspiciousPackages.length; i++) {
                if (pkg === suspiciousPackages[i]) {
                    isSuspicious = true;
                    break;
                }
            }
            if (isSuspicious) {
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                send({
                    group: "anti_analysis",
                    api: "PackageManager.getPackageInfo",
                    args: {package: pkg, flags: flags, suspicious: true},
                    stack: stack.substring(0, 500)
                });
            }
            return result;
        };
    } catch (e) {}

    // Settings.Secure - checking for ADB enabled, etc.
    try {
        var SettingsSecure = Java.use("android.provider.Settings$Secure");
        var getInt = SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String');
        getInt.implementation = function (resolver, name) {
            var result = this.getInt(resolver, name);
            var suspiciousSettings = [
                "adb_enabled", "development_settings_enabled",
                "install_non_market_apps", "unknown_sources"
            ];
            var isSuspicious = false;
            for (var i = 0; i < suspiciousSettings.length; i++) {
                if (name === suspiciousSettings[i]) {
                    isSuspicious = true;
                    break;
                }
            }
            if (isSuspicious) {
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                send({
                    group: "anti_analysis",
                    api: "Settings.Secure.getInt",
                    args: {setting: name, value: result},
                    stack: stack.substring(0, 500)
                });
            }
            return result;
        };
    } catch (e) {}

    // Network interface enumeration - checking for emulators
    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");
        var getNetworkInterfaces = NetworkInterface.getNetworkInterfaces.overload();
        getNetworkInterfaces.implementation = function () {
            var result = this.getNetworkInterfaces();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "anti_analysis",
                api: "NetworkInterface.getNetworkInterfaces",
                args: {},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}
});