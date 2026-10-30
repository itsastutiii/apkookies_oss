// Frida hook: SMS interception and sending
// Monitors SMS sending APIs and incoming SMS parsing.
//
// Tested with:
// Android emulator
// Frida 16.7.19

Java.perform(function () {

    var Exception = Java.use("java.lang.Exception");
    var Log = Java.use("android.util.Log");

    function getStack() {
        try {
            return Log.getStackTraceString(Exception.$new()).substring(0, 500);
        } catch (e) {
            return "";
        }
    }

    function safeString(value) {
        try {
            return value ? value.toString() : null;
        } catch (e) {
            return null;
        }
    }

    // =========================================================
    // SMS SENDING
    // =========================================================

    try {
        var SmsManager = Java.use("android.telephony.SmsManager");

        // -----------------------------------------------------
        // sendTextMessage
        // -----------------------------------------------------

        try {
            var sendTextMessage = SmsManager.sendTextMessage.overload(
                "java.lang.String",
                "java.lang.String",
                "java.lang.String",
                "android.app.PendingIntent",
                "android.app.PendingIntent"
            );

            sendTextMessage.implementation = function (
                destAddr,
                scAddr,
                text,
                sentIntent,
                deliveryIntent
            ) {

                send({
                    group: "sms",
                    api: "SmsManager.sendTextMessage",
                    args: {
                        destAddr: safeString(destAddr),
                        text: text
                            ? text.toString().substring(0, 200)
                            : null,
                        hasScAddr: scAddr !== null
                    },
                    stack: getStack()
                });

                return sendTextMessage.call(
                    this,
                    destAddr,
                    scAddr,
                    text,
                    sentIntent,
                    deliveryIntent
                );
            };

        } catch (e) {

            send({
                group: "sms",
                api: "hook_error",
                args: {
                    api: "sendTextMessage",
                    error: e.toString()
                }
            });
        }


        // -----------------------------------------------------
        // sendMultipartTextMessage
        //
        // Android version in your emulator exposes:
        //
        // String
        // String
        // ArrayList
        // ArrayList
        // ArrayList
        // -----------------------------------------------------

        try {
            var sendMultipartTextMessage =
                SmsManager.sendMultipartTextMessage.overload(
                    "java.lang.String",
                    "java.lang.String",
                    "java.util.ArrayList",
                    "java.util.ArrayList",
                    "java.util.ArrayList"
                );

            sendMultipartTextMessage.implementation = function (
                destAddr,
                scAddr,
                parts,
                sentIntents,
                deliveryIntents
            ) {

                var partTexts = [];

                try {
                    if (parts !== null) {
                        for (var i = 0; i < parts.size(); i++) {

                            var part = parts.get(i);

                            if (part !== null) {
                                partTexts.push(
                                    part.toString().substring(0, 200)
                                );
                            }
                        }
                    }
                } catch (e) {
                    partTexts.push("[Unable to read SMS parts]");
                }

                send({
                    group: "sms",
                    api: "SmsManager.sendMultipartTextMessage",
                    args: {
                        destAddr: safeString(destAddr),
                        parts: partTexts,
                        partCount: parts ? parts.size() : 0,
                        hasScAddr: scAddr !== null
                    },
                    stack: getStack()
                });

                return sendMultipartTextMessage.call(
                    this,
                    destAddr,
                    scAddr,
                    parts,
                    sentIntents,
                    deliveryIntents
                );
            };

        } catch (e) {

            send({
                group: "sms",
                api: "hook_error",
                args: {
                    api: "sendMultipartTextMessage",
                    error: e.toString()
                }
            });
        }

    } catch (e) {

        send({
            group: "sms",
            api: "init_error",
            args: {
                error: e.toString()
            }
        });
    }


    // =========================================================
    // INCOMING SMS
    // =========================================================

    try {

        var SmsMessage =
            Java.use("android.telephony.SmsMessage");

        var createFromPdu =
            SmsMessage.createFromPdu.overload("[B");

        createFromPdu.implementation = function (pdu) {

            var result = createFromPdu.call(this, pdu);

            try {

                var originatingAddress =
                    result.getOriginatingAddress();

                var messageBody =
                    result.getMessageBody();

                var timestampMillis =
                    result.getTimestampMillis();

                send({
                    group: "sms",
                    api: "SmsMessage.createFromPdu",
                    args: {
                        originatingAddress:
                            safeString(originatingAddress),

                        messageBody:
                            messageBody
                                ? messageBody.toString().substring(0, 200)
                                : null,

                        timestampMillis:
                            timestampMillis
                    },

                    stack: getStack()
                });

            } catch (e) {

                send({
                    group: "sms",
                    api: "SmsMessage.createFromPdu.error",
                    args: {
                        error: e.toString()
                    },
                    stack: getStack()
                });
            }

            return result;
        };

    } catch (e) {

        send({
            group: "sms",
            api: "hook_error",
            args: {
                api: "SmsMessage.createFromPdu",
                error: e.toString()
            }
        });
    }


    // =========================================================
    // SMS_RECEIVED BROADCAST
    // =========================================================

    try {

        var BroadcastReceiver =
            Java.use("android.content.BroadcastReceiver");

        var onReceive =
            BroadcastReceiver.onReceive.overload(
                "android.content.Context",
                "android.content.Intent"
            );

        onReceive.implementation = function (
            context,
            intent
        ) {

            try {

                if (
                    intent !== null &&
                    intent.getAction() ===
                        "android.provider.Telephony.SMS_RECEIVED"
                ) {

                    send({
                        group: "sms",
                        api:
                            "BroadcastReceiver.onReceive(SMS_RECEIVED)",

                        args: {
                            action:
                                intent.getAction()
                        },

                        stack: getStack()
                    });
                }

            } catch (e) {

                send({
                    group: "sms",
                    api: "BroadcastReceiver.error",
                    args: {
                        error: e.toString()
                    },
                    stack: getStack()
                });
            }

            return onReceive.call(
                this,
                context,
                intent
            );
        };

    } catch (e) {

        // BroadcastReceiver may not be directly hookable
        // on every Android configuration.

        send({
            group: "sms",
            api: "BroadcastReceiver.hook_unavailable",
            args: {
                error: e.toString()
            }
        });
    }


    // =========================================================
    // READY
    // =========================================================

    send({
        group: "sms",
        api: "sms_hooks_initialized",
        args: {
            sendTextMessage: true,
            sendMultipartTextMessage: true,
            createFromPdu: true,
            smsReceivedBroadcast: true
        }
    });

});