package com.example.pvcbbankcapture;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.KeyEvent;
import android.widget.Toast;

import java.util.Arrays;
import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "PvcbBankCapture";
    private static final String TARGET_PKG = "com.pvcombank.retail";
    private static final List<String> TARGET_HEADERS = Arrays.asList(
            "x-api-key", "x-kony-app-key", "x-kony-app-secret", 
            "client-id", "x-kony-reportingparams", "authorization", 
            "device-id"
    );

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals(TARGET_PKG)) return;
        
        XposedBridge.log(TAG + ": Loaded into " + lpparam.packageName);

        // 1. Hook OCRAModule for OTP
        try {
            XposedBridge.log(TAG + " Attempting to find class: vn.com.pvcombank.RNOcra.OCRAModule");
            Class<?> ocraClass = XposedHelpers.findClass("vn.com.pvcombank.RNOcra.OCRAModule", lpparam.classLoader);
            XposedBridge.log(TAG + " Found class: vn.com.pvcombank.RNOcra.OCRAModule");

            XposedBridge.hookAllMethods(ocraClass, "generateOCRA", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log(TAG + " [OCRA] generateOCRA called");
                    for (int i = 0; i < param.args.length; i++) {
                         XposedBridge.log(TAG + "   Arg[" + i + "]: " + param.args[i]);
                    }
                    if (param.args.length > 1 && param.args[1] != null) {
                         String otp = param.args[1].toString();
                         XposedBridge.log(TAG + " Found OTP (generateOCRA): " + otp);
                         CaptureInfo.update("otp", otp);
                    }
                }
            });
            XposedBridge.log(TAG + " Hooked generateOCRA");

            // Hook OCRA_generateOCRA (Bridge method)
             XposedBridge.hookAllMethods(ocraClass, "OCRA_generateOCRA", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log(TAG + " [OCRA] OCRA_generateOCRA called");
                    for (int i = 0; i < param.args.length; i++) {
                         XposedBridge.log(TAG + "   Arg[" + i + "]: " + param.args[i]);
                    }
                    if (param.args.length > 1 && param.args[1] != null) {
                        String otp = param.args[1].toString();
                        XposedBridge.log(TAG + " Found OTP (OCRA_generateOCRA): " + otp);
                        CaptureInfo.update("otp", otp);
                    }
                }
            });
            XposedBridge.log(TAG + " Hooked OCRA_generateOCRA");

        } catch (Throwable t) {
            XposedBridge.log(TAG + " Failed to hook OCRAModule (vn.com.pvcombank.RNOcra.OCRAModule): " + t);
        }

        // 2. Hook OkHttp Request Builder to capture Headers
        try {
            // Find OkHttp3 Request Class
            Class<?> requestClass = XposedHelpers.findClass("okhttp3.Request", lpparam.classLoader);
            Class<?> okHttpClientClass = XposedHelpers.findClass("okhttp3.OkHttpClient", lpparam.classLoader);
            
            XposedHelpers.findAndHookMethod(okHttpClientClass, "newCall", requestClass, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object request = param.args[0];
                    if (request == null) return;

                    try {
                        Object headersObj = XposedHelpers.callMethod(request, "headers");
                        if (headersObj != null) {
                             int size = (int) XposedHelpers.callMethod(headersObj, "size");
                             for (int i = 0; i < size; i++) {
                                 String name = (String) XposedHelpers.callMethod(headersObj, "name", i);
                                 String value = (String) XposedHelpers.callMethod(headersObj, "value", i);
                                 
                                 if (name != null) {
                                     String lowerName = name.toLowerCase();
                                     if (TARGET_HEADERS.contains(lowerName)) {
                                         CaptureInfo.update(lowerName, value);
                                     }
                                 }
                             }
                        }
                    } catch (Exception e) {
                        XposedBridge.log(TAG + " Error analyzing request: " + e);
                    }
                }
            });
             XposedBridge.log(TAG + " Hooked OkHttpClient.newCall");

        } catch (Throwable t) {
             XposedBridge.log(TAG + " Failed to hook OkHttp: " + t);
        }

        // 3. Volume Key Listener for Copy (Improved)
        try {
             XC_MethodHook activityHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    KeyEvent event = (KeyEvent) param.args[0];
                    int keyCode = event.getKeyCode();
                    
                    // Simple logging for debug
                    // XposedBridge.log(TAG + " Key Event: " + keyCode + " Action: " + event.getAction());

                    if (event.getAction() != KeyEvent.ACTION_DOWN) return;

                    // VOLUME UP: Copy Info
                    if (keyCode == KeyEvent.KEYCODE_VOLUME_UP) {
                        try {
                            Activity activity = (Activity) param.thisObject;
                            
                            String jsonStr = CaptureInfo.toJson();
                            XposedBridge.log("\n[+] 📋 Copying Headers: " + jsonStr);

                            ClipboardManager clipboard = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                            ClipData clip = ClipData.newPlainText("PvcbHeaders", jsonStr);
                            clipboard.setPrimaryClip(clip);

                             activity.runOnUiThread(() -> 
                                Toast.makeText(activity, "Headers Copied!", Toast.LENGTH_SHORT).show()
                             );
                             
                             param.setResult(true); // Consume event

                        } catch (Exception e) {
                            XposedBridge.log(TAG + " Copy Failed: " + e);
                        }
                    } 
                }
            };

            XposedHelpers.findAndHookMethod(Activity.class, "dispatchKeyEvent", KeyEvent.class, activityHook);
            // Also try onKeyUp as backup on some devices
            // XposedHelpers.findAndHookMethod(Activity.class, "onKeyUp", int.class, KeyEvent.class, ...);

            XposedBridge.log("[+] Volume Control Enabled (Up=Copy)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Hook Activity Failed: " + t);
        }
    }
}
