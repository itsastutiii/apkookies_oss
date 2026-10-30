# Benign firing rates: CICMalDroid 2020 (permissions only)

Apps: {'malicious': 9803, 'benign': 1795}. A hard-override rule must fire on < 1% of benign apps.

## Rules (category: None)

| rule | benign | malicious |
|---|---|---|

## Rules (category: Banking)

| rule | benign | malicious |
|---|---|---|
| R001_SMS_INTERCEPT_NONCOMM | 7.7% | 67.8% |

## Knowledge-graph edges (fires for every app of that category that has the capability)

| edge | benign rate if the app is in that category | source |
|---|---|---|
| SmsInterception ANOMALOUS_FOR Game | 7.7% | Google Play policy 'Use of SMS or Call Log permission groups' (https://support.google.com/googleplay/android-developer/answer/10208820): only the default SMS/Phone handler, or a listed exception, may request these. Link written from memory; verify. |
| SmsInterception ANOMALOUS_FOR Wallpaper | 7.7% | Google Play policy 'Use of SMS or Call Log permission groups' (https://support.google.com/googleplay/android-developer/answer/10208820): only the default SMS/Phone handler, or a listed exception, may request these. Link written from memory; verify. |
| SmsInterception NORMAL_FOR Communication | 7.7% | Google Play policy 'Use of SMS or Call Log permission groups' (https://support.google.com/googleplay/android-developer/answer/10208820): only the default SMS/Phone handler, or a listed exception, may request these. Link written from memory; verify. |
| AccessibilityAbuse ANOMALOUS_FOR Banking | 0.6% | Google Play AccessibilityService API policy (https://support.google.com/googleplay/android-developer/answer/10964491): only apps that help people with disabilities, or listed exceptions (e.g. password managers, automation), may use it. Benign firing 0.6% on CICMalDroid. |
| AccessibilityAbuse ANOMALOUS_FOR Game | 0.6% | Google Play AccessibilityService API policy (https://support.google.com/googleplay/android-developer/answer/10964491): only apps that help people with disabilities, or listed exceptions (e.g. password managers, automation), may use it. Benign firing 0.6% on CICMalDroid. |
| AccessibilityAbuse ANOMALOUS_FOR Wallpaper | 0.6% | Google Play AccessibilityService API policy (https://support.google.com/googleplay/android-developer/answer/10964491): only apps that help people with disabilities, or listed exceptions (e.g. password managers, automation), may use it. Benign firing 0.6% on CICMalDroid. |

## Hard-override check

Violations: none
