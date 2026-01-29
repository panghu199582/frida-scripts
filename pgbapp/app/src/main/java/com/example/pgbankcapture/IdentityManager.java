package com.example.pgbankcapture;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;

import java.util.Random;
import java.util.UUID;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class IdentityManager {

    private static final String PREFS_NAME = "identity_spoof";
    private static final String TAG = "PgbankIdentity";

    // Defaults (Initialized immediately to prevent nulls)
    private static String fakeSerial = "SPOOF_INIT";
    private static String fakeModel = "Pixel 6a";
    private static String fakeManufacturer = "Google";
    private static String fakeFingerprint = "google/bluejay/bluejay:13/TP1A.220624.014/8819520:user/release-keys";
    private static String fakeAndroidId = "deadbeef12345678";

    // Initialize random defaults in static block
    static {
       fakeSerial = "SPOOF_" + randomString(10);
       fakeModel = "Pixel " + (10 + new Random().nextInt(10)) + " Pro";
       fakeManufacturer = "Google_Spoof_" + randomString(4);
       fakeFingerprint = "google/bluejay/bluejay:13/" + randomString(10) + ":user/release-keys";
       fakeAndroidId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedBridge.log(TAG + " Init: Setting Temporary Fake Identity: " + fakeSerial);
        updateStaticFields();
        applyHooks(lpparam);
    }

    public static void loadFromContext(Context context) {
        try {
            SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            if (prefs.contains("serial")) {
                // Load saved identity
                fakeSerial = prefs.getString("serial", fakeSerial);
                fakeModel = prefs.getString("model", fakeModel);
                fakeManufacturer = prefs.getString("manufacturer", fakeManufacturer);
                fakeFingerprint = prefs.getString("fingerprint", fakeFingerprint);
                fakeAndroidId = prefs.getString("android_id", fakeAndroidId);
                
                XposedBridge.log(TAG + " Loaded Persistent Identity: " + fakeSerial);
                updateStaticFields();
            } else {
                // No saved identity, save the current temporary one (making it persistent)
                saveIdentity(context);
                XposedBridge.log(TAG + " Persisted Temporary Identity: " + fakeSerial);
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + " loadFromContext Error: " + t);
        }
    }

    public static void generateNew(Context context) {
        fakeSerial = "SPOOF_" + randomString(10);
        fakeModel = "Pixel " + (10 + new Random().nextInt(10)) + " Pro";
        fakeManufacturer = "Google_Spoof_" + randomString(4);
        fakeFingerprint = "google/bluejay/bluejay:13/" + randomString(10) + ":user/release-keys";
        fakeAndroidId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        XposedBridge.log(TAG + " Generated NEW Identity: " + fakeSerial);
        
        updateStaticFields();
        saveIdentity(context);
    }

    private static void saveIdentity(Context context) {
        try {
             SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
             editor.putString("serial", fakeSerial);
             editor.putString("model", fakeModel);
             editor.putString("manufacturer", fakeManufacturer);
             editor.putString("fingerprint", fakeFingerprint);
             editor.putString("android_id", fakeAndroidId);
             editor.apply(); 
        } catch (Throwable t) {
             XposedBridge.log(TAG + " Save Error: " + t);
        }
    }

    private static void updateStaticFields() {
        /*
        try {
            XposedHelpers.setStaticObjectField(Build.class, "SERIAL", fakeSerial);
            XposedHelpers.setStaticObjectField(Build.class, "MODEL", fakeModel);
            XposedHelpers.setStaticObjectField(Build.class, "MANUFACTURER", fakeManufacturer);
            XposedHelpers.setStaticObjectField(Build.class, "FINGERPRINT", fakeFingerprint);
            XposedHelpers.setStaticObjectField(Build.class, "PRODUCT", "bluejay_fake");
            XposedHelpers.setStaticObjectField(Build.class, "DEVICE", "bluejay_fake");
            XposedHelpers.setStaticObjectField(Build.class, "HARDWARE", "tensor_fake");
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Failed to update static fields: " + t);
        }
        */
        XposedBridge.log(TAG + " Static field modification disabled for stability.");
    }

    private static void applyHooks(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook Build.getSerial()
        try {
             XposedHelpers.findAndHookMethod(Build.class, "getSerial", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                   // Ensure we return non-null
                   if (fakeSerial != null) param.setResult(fakeSerial);
                }
            });
        } catch (Throwable t) {}

        // Hook Settings.Secure.getString for Android ID
        try {
            XposedHelpers.findAndHookMethod(Settings.Secure.class, "getString", android.content.ContentResolver.class, String.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if ("android_id".equals(param.args[1])) {
                        if (fakeAndroidId != null) {
                            param.setResult(fakeAndroidId);
                        }
                    }
                }
            });
        } catch (Throwable t) {}
    }

    private static String randomString(int len) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder();
        Random rnd = new Random();
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
