package com.fixture.bad;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

/** Test fixture: accessibility service that clicks on the user's behalf. Never executed. */
public class A11y extends AccessibilityService {
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root != null) {
            root.performAction(AccessibilityNodeInfo.ACTION_CLICK);
        }
        performGlobalAction(GLOBAL_ACTION_BACK);
    }

    @Override
    public void onInterrupt() {
    }
}
