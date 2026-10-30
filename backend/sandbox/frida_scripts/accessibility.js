// Frida hook: Accessibility Service abuse
// Monitors AccessibilityService lifecycle and event handling

Java.perform(function () {
    // AccessibilityService.onAccessibilityEvent
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        var onAccessibilityEvent = AccessibilityService.onAccessibilityEvent.overload('android.view.accessibility.AccessibilityEvent');
        onAccessibilityEvent.implementation = function (event) {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            var eventType = event.getEventType();
            var eventTypeStr = eventTypeToString(eventType);
            var className = event.getClassName ? event.getClassName().toString() : "null";
            var packageName = event.getPackageName ? event.getPackageName().toString() : "null";
            var text = [];
            if (event.getText) {
                var t = event.getText();
                for (var i = 0; i < t.size(); i++) {
                    var s = t.get(i);
                    if (s) text.push(s.toString().substring(0, 200));
                }
            }
            send({
                group: "accessibility",
                api: "AccessibilityService.onAccessibilityEvent",
                args: {
                    eventType: eventTypeStr,
                    className: className,
                    packageName: packageName,
                    text: text,
                    eventTime: event.getEventTime ? event.getEventTime() : 0
                },
                stack: stack.substring(0, 500)
            });
            return this.onAccessibilityEvent(event);
        };
    } catch (e) {
        send({group: "accessibility", api: "init_error", args: {error: e.toString()}});
    }

    // AccessibilityService.onInterrupt
    try {
        var onInterrupt = AccessibilityService.onInterrupt;
        onInterrupt.implementation = function () {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "accessibility",
                api: "AccessibilityService.onInterrupt",
                args: {},
                stack: stack.substring(0, 500)
            });
            return this.onInterrupt();
        };
    } catch (e) {}

    // AccessibilityService.onServiceConnected
    try {
        var onServiceConnected = AccessibilityService.onServiceConnected.overload();
        onServiceConnected.implementation = function () {
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "accessibility",
                api: "AccessibilityService.onServiceConnected",
                args: {},
                stack: stack.substring(0, 500)
            });
            return this.onServiceConnected();
        };
    } catch (e) {}

    // AccessibilityManager - check if accessibility is enabled
    try {
        var AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        var isEnabled = AccessibilityManager.isEnabled;
        isEnabled.implementation = function () {
            var result = this.isEnabled();
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            send({
                group: "accessibility",
                api: "AccessibilityManager.isEnabled",
                args: {result: result},
                stack: stack.substring(0, 500)
            });
            return result;
        };
    } catch (e) {}

    // WindowManager.LayoutParams - detect TYPE_APPLICATION_OVERLAY (overlay permission)
    try {
        var WindowManager = Java.use("android.view.WindowManager");
        var LayoutParams = Java.use("android.view.WindowManager$LayoutParams");
        // Hook addView to detect overlay windows
        var ViewGroup = Java.use("android.view.ViewGroup");
        var addView = ViewGroup.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
        addView.implementation = function (view, params) {
            if (params && params.type === LayoutParams.TYPE_APPLICATION_OVERLAY.value) {
                var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                send({
                    group: "accessibility",
                    api: "ViewGroup.addView(TYPE_APPLICATION_OVERLAY)",
                    args: {
                        viewClass: view.getClass().getName()
                    },
                    stack: stack.substring(0, 500)
                });
            }
            return this.addView(view, params);
        };
    } catch (e) {}

    function eventTypeToString(type) {
        var types = {
            1: "TYPE_TOUCH_EXPLORATION_GESTURE_START",
            2: "TYPE_TOUCH_EXPLORATION_GESTURE_END",
            4: "TYPE_VIEW_CLICKED",
            8: "TYPE_VIEW_LONG_CLICKED",
            16: "TYPE_VIEW_SELECTED",
            32: "TYPE_VIEW_FOCUSED",
            64: "TYPE_VIEW_SCROLLED",
            128: "TYPE_VIEW_TEXT_CHANGED",
            256: "TYPE_WINDOW_STATE_CHANGED",
            512: "TYPE_WINDOW_CONTENT_CHANGED",
            1024: "TYPE_VIEW_ACCESSIBILITY_FOCUSED",
            2048: "TYPE_VIEW_TEXT_SELECTION_CHANGED",
            4096: "TYPE_ASSIST_READING_CONTEXT",
            8192: "TYPE_GESTURE_DETECTION_START",
            16384: "TYPE_GESTURE_DETECTION_END",
            32768: "TYPE_TOUCH_INTERACTION_START",
            65536: "TYPE_TOUCH_INTERACTION_END",
            131072: "TYPE_WINDOWS_CHANGED",
            262144: "TYPE_VIEW_HOVER_ENTER",
            524288: "TYPE_VIEW_HOVER_EXIT",
            1048576: "TYPE_TOUCH_EXPLORATION_GESTURE_START",
            2097152: "TYPE_TOUCH_EXPLORATION_GESTURE_END"
        };
        return types[type] || "TYPE_UNKNOWN(" + type + ")";
    }
});