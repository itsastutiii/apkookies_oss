package com.fixture.bad;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.telephony.SmsManager;
import android.telephony.SmsMessage;

/** Test fixture: SMS send / read / inbox query (OTP-stealer pattern). Never executed. */
public class SmsSpy {
    public void forward(String to, String body) {
        SmsManager.getDefault().sendTextMessage(to, null, body, null, null);
    }

    public String read(byte[] pdu) {
        SmsMessage m = SmsMessage.createFromPdu(pdu);
        return m.getMessageBody();
    }

    public Cursor inbox(Context c) {
        return c.getContentResolver().query(Uri.parse("content://sms/inbox"), null, null, null, null);
    }
}
