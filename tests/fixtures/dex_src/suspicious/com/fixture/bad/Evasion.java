package com.fixture.bad;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.telephony.TelephonyManager;
import java.io.File;

/** Test fixture: emulator / debugger / root checks, SIM gating, delayed alarm. Never executed. */
public class Evasion {
    public boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.HARDWARE.contains("goldfish")
                || new File("/dev/socket/qemud").exists();
    }

    public boolean isDebugged() {
        return Debug.isDebuggerConnected();
    }

    public boolean isRooted() {
        return new File("/system/xbin/su").exists();
    }

    public String simCountry(Context c) {
        TelephonyManager tm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
        return tm.getSimCountryIso();
    }

    public void stall(Context c, PendingIntent pi) {
        AlarmManager am = (AlarmManager) c.getSystemService(Context.ALARM_SERVICE);
        am.setExact(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 86_400_000L, pi);
    }
}
