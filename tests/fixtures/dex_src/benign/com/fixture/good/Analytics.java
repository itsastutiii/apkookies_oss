package com.fixture.good;

import android.os.Build;
import android.util.Log;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Test fixture: ordinary app code full of DECOY TEXT that naive string matching
 * flags ("SmsManager", "goldfish", "/system/xbin/su", "addJavascriptInterface")
 * without ever calling those APIs. Never executed.
 */
public class Analytics {
    public String deviceInfo() {
        // Reading Build fields for analytics is normal; no emulator strings here.
        return Build.MODEL + " / " + Build.MANUFACTURER;
    }

    public void decoys() {
        Log.i("demo", "This app never uses android/telephony/SmsManager or SmsManager");
        Log.i("demo", "goldfish is a pet; /system/xbin/su is a path in a tutorial");
        Log.i("demo", "addJavascriptInterface and Debug.isDebuggerConnected are only words here");
    }

    public int ping() throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL("https://example.com").openConnection();
        return c.getResponseCode();
    }
}
