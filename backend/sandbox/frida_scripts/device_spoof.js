// APKookies - Device Identity Runtime Instrumentation
//
// Controlled test hook.
// This does NOT change the physical/emulator device.
// It intercepts selected Android identity APIs and returns
// explicitly supplied test values.
//
// Configuration is supplied from Python through Frida RPC.

var spoofConfig = {};

var configured = false;
var hooksInstalled = false;

function installHooks() {

    if (hooksInstalled) {
        return;
    }

    Java.perform(function () {

        // ============================================================
        // ANDROID ID
        // ============================================================

        if (spoofConfig.androidId) {

            try {

                var SettingsSecure =
                    Java.use("android.provider.Settings$Secure");

                var getString =
                    SettingsSecure.getString.overload(
                        "android.content.ContentResolver",
                        "java.lang.String"
                    );

                getString.implementation = function (resolver, name) {

                    if (name === "android_id") {

                        send({
                            group: "device_spoof",
                            api: "Settings.Secure.getString(android_id)",
                            args: {
                                spoofed: spoofConfig.androidId
                            }
                        });

                        return spoofConfig.androidId;
                    }

                    return getString.call(
                        this,
                        resolver,
                        name
                    );
                };

                send({
                    group: "device_spoof",
                    api: "android_id_hook_initialized",
                    args: {
                        enabled: true
                    }
                });

            } catch (e) {

                send({
                    group: "device_spoof",
                    api: "android_id_hook_error",
                    args: {
                        error: e.toString()
                    }
                });
            }
        }


        // ============================================================
        // TELEPHONY / IMEI
        // ============================================================

        if (spoofConfig.imei) {

            try {

                var TelephonyManager =
                    Java.use("android.telephony.TelephonyManager");

                var getImei =
                    TelephonyManager.getImei.overload();

                getImei.implementation = function () {

                    send({
                        group: "device_spoof",
                        api: "TelephonyManager.getImei",
                        args: {
                            spoofed: spoofConfig.imei
                        }
                    });

                    return spoofConfig.imei;
                };

                send({
                    group: "device_spoof",
                    api: "imei_hook_initialized",
                    args: {
                        enabled: true
                    }
                });

            } catch (e) {

                send({
                    group: "device_spoof",
                    api: "imei_hook_error",
                    args: {
                        error: e.toString()
                    }
                });
            }
        }


        // ============================================================
        // SIM SERIAL
        // ============================================================

        if (spoofConfig.simSerial) {

            try {

                var TelephonyManagerSim =
                    Java.use("android.telephony.TelephonyManager");

                var getSimSerialNumber =
                    TelephonyManagerSim
                        .getSimSerialNumber
                        .overload();

                getSimSerialNumber.implementation = function () {

                    send({
                        group: "device_spoof",
                        api: "TelephonyManager.getSimSerialNumber",
                        args: {
                            spoofed: spoofConfig.simSerial
                        }
                    });

                    return spoofConfig.simSerial;
                };

                send({
                    group: "device_spoof",
                    api: "sim_serial_hook_initialized",
                    args: {
                        enabled: true
                    }
                });

            } catch (e) {

                send({
                    group: "device_spoof",
                    api: "sim_serial_hook_error",
                    args: {
                        error: e.toString()
                    }
                });
            }
        }


        // ============================================================
        // PHONE NUMBER
        // ============================================================

        if (spoofConfig.phoneNumber) {

            try {

                var TelephonyManagerPhone =
                    Java.use("android.telephony.TelephonyManager");

                var getLine1Number =
                    TelephonyManagerPhone
                        .getLine1Number
                        .overload();

                getLine1Number.implementation = function () {

                    send({
                        group: "device_spoof",
                        api: "TelephonyManager.getLine1Number",
                        args: {
                            spoofed: spoofConfig.phoneNumber
                        }
                    });

                    return spoofConfig.phoneNumber;
                };

                send({
                    group: "device_spoof",
                    api: "phone_number_hook_initialized",
                    args: {
                        enabled: true
                    }
                });

            } catch (e) {

                send({
                    group: "device_spoof",
                    api: "phone_number_hook_error",
                    args: {
                        error: e.toString()
                    }
                });
            }
        }


        hooksInstalled = true;

        send({
            group: "device_spoof",
            api: "spoof_hooks_initialized",
            args: {
                androidId: !!spoofConfig.androidId,
                imei: !!spoofConfig.imei,
                simSerial: !!spoofConfig.simSerial,
                phoneNumber: !!spoofConfig.phoneNumber
            }
        });
    });
}


// ================================================================
// FRIDA RPC
// ================================================================

rpc.exports = {

    configure: function (config) {

        spoofConfig = config || {};
        configured = true;

        send({
            group: "device_spoof",
            api: "configuration_received",
            args: {
                androidId: !!spoofConfig.androidId,
                imei: !!spoofConfig.imei,
                simSerial: !!spoofConfig.simSerial,
                phoneNumber: !!spoofConfig.phoneNumber
            }
        });

        // Install hooks AFTER configuration has arrived.
        installHooks();

        return true;
    }
};


// ================================================================
// WAIT FOR CONFIGURATION
// ================================================================

Java.perform(function () {

    send({
        group: "device_spoof",
        api: "script_initialized",
        args: {
            waiting_for_configuration: true
        }
    });

});