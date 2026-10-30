package com.fixture.bad;

import android.content.Context;
import android.provider.Settings;
import android.view.View;
import android.view.WindowManager;
import android.webkit.WebView;

/** Test fixture: overlay window + JavaScript bridge. Never executed. */
public class Overlay {
    public void show(Context c, View v) {
        if (Settings.canDrawOverlays(c)) {
            WindowManager wm = (WindowManager) c.getSystemService(Context.WINDOW_SERVICE);
            wm.addView(v, new WindowManager.LayoutParams(
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY));
        }
    }

    public void bridge(WebView w, Object o) {
        w.getSettings().setJavaScriptEnabled(true);
        w.addJavascriptInterface(o, "bridge");
    }
}
