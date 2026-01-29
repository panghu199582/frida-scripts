package com.example.pgbankcapture;

import android.app.Activity;
import android.app.Application;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.KeyEvent;
import android.widget.Toast;
import android.util.Log;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.io.FileDescriptor;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import javax.crypto.Cipher;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "PgbankCapture";
    private static final String TARGET_PKG = "pgbankApp.pgbank.com.vn";

    // Track Cipher instances (Best effort for mode tracking)
    private static final Map<Cipher, Integer> cipherModes = Collections.synchronizedMap(new WeakHashMap<>());

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        try {
            if (!lpparam.packageName.equals(TARGET_PKG)) return;
            
            XposedBridge.log(TAG + ": Loaded into " + lpparam.packageName);

            // 1. Init Identity Spoofing
            try {
                IdentityManager.init(lpparam);
            } catch (Throwable t) {
                XposedBridge.log(TAG + " IdentityManager Init Failed: " + t);
            }

            // 2. Hook Application.onCreate to LOAD Persistent Identity
            try {
                XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        final Context context = (Context) param.thisObject;
                        if (context != null) {
                             new Thread(() -> {
                                 IdentityManager.loadFromContext(context);
                             }).start();
                        }
                    }
                });
            } catch (Throwable t) {
                 XposedBridge.log(TAG + " App.onCreate Hook Failed: " + t);
            }

            // ================== UTILS ==================
            final class Utils {
                String byteArrayToString(byte[] bytes) {
                    if (bytes == null) return null;
                    try {
                        String str = new String(bytes, StandardCharsets.UTF_8);
                        int readable = 0;
                        int len = Math.min(str.length(), 100);
                        for (int i = 0; i < len; i++) {
                            char c = str.charAt(i);
                            if ((c >= 32 && c <= 126) || c == 10 || c == 13) readable++;
                        }
                        if (len > 0 && ((double) readable / len) > 0.8) {
                            return str;
                        }
                    } catch (Exception e) {}
                    return null;
                }

                 void inspectKey(String str, String tag) {
                    if (str == null) return;
                    if (str.length() == 39 && str.startsWith("DEV")) {
                        if (CaptureInfo.addFoundKey(str)) {
                            XposedBridge.log("\n[+] 🔑 Found OTP Secret Key (" + tag + "): " + str);
                            CaptureInfo.update("otpSecretKey", str);
                        }
                    }
                }
                
                 void tryParseJson(java.nio.ByteBuffer buffer, String tag) {
                     if (buffer == null) return;
                     try {
                         byte[] bytes = null;
                         if (buffer.hasArray()) {
                             bytes = buffer.array();
                         } else {
                             if (buffer.capacity() > 0) {
                                 int oldPos = buffer.position();
                                 buffer.position(0);
                                 int readLen = Math.min(buffer.capacity(), 1024 * 50); 
                                 bytes = new byte[readLen];
                                 buffer.get(bytes);
                                 buffer.position(oldPos); // RESTORE
                             }
                         }
                         if (bytes != null) tryParseJson(bytes, tag);
                     } catch (Exception e) {}
                 }

                 void tryParseJson(byte[] bytes, String tag) {
                     if (bytes == null || bytes.length == 0) return;
                     try {
                         String rawStr = new String(bytes, StandardCharsets.UTF_8);
                         String trimmed = rawStr.trim();
                         
                         // Strict filter to avoid log spam
                         if (!trimmed.startsWith("{") && !trimmed.contains("clientDeviceID")) return;

                         JSONObject json = new JSONObject(trimmed);
                         boolean updated = false;
                         String[] keys = {"clientDeviceID", "devicePubKey", "deviceId", "TMK", "userID", "phone_no", "deviceName", "deviceKey"};
                         for (String k : keys) {
                             if (json.has(k)) {
                                 if (k == "deviceKey") {
                                    CaptureInfo.update("otpSecretKey", json.getString(k));
                                 }else{
                                    CaptureInfo.update(k, json.getString(k));
                                 }
                                 
                                 updated = true;
                             }
                         }
                         if (updated) {
                            //  XposedBridge.log("\n[+] 📦 Captured Body Params (" + tag + "):\n" + CaptureInfo.toJson());
                         }
                     } catch (Exception e) {}
                 }

                 void tryParseHttp(byte[] bytes, String tag) {
                     if (bytes == null || bytes.length == 0) return;
                     try {
                         // Relaxed check: Print if it looks mostly printable
                         int len = Math.min(bytes.length, 256);
                         int printable = 0;
                         for(int i=0; i<len; i++) {
                             byte b = bytes[i];
                             if ((b >= 32 && b <= 126) || b == 10 || b == 13) printable++;
                         }
                         if (((double)printable / len) < 0.8) return; // Skip if >20% binary

                         String str = new String(bytes, StandardCharsets.UTF_8);
                         // Allow any non-empty string that passed the printable check
                         if (str.length() > 2) {
                             XposedBridge.log("\n🌐 [" + tag + "] (" + bytes.length + " bytes):\n" + str);
                         }
                     } catch (Exception e) {}
                 }
             }
            final Utils utils = new Utils();

            // ================== PROTOCOL HIJACK & HASH ==================
            hookProtocolHijack(lpparam);
            hookHashFunctions(lpparam, utils);
            hookFullHttpLogging(lpparam, utils);

            // ================== KEY CAPTURE ==================
            // SecretKeySpec Hook
            try {
                XC_MethodHook keyHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            byte[] keyBytes = (byte[]) param.args[0];
                            String algo = (param.args.length > 1 && param.args[param.args.length - 1] instanceof String) 
                                ? (String) param.args[param.args.length - 1] : "Unknown";
                                
                            // Offset/Len check
                            if (param.args.length >= 3 && param.args[1] instanceof Integer && param.args[2] instanceof Integer) {
                                int offset = (int) param.args[1];
                                int len = (int) param.args[2];
                                 if (len == 39) {
                                      String s = new String(keyBytes, offset, len, StandardCharsets.UTF_8);
                                      if (s.startsWith("DEV")) utils.inspectKey(s, "SecretKeySpec(Off)");
                                 }
                            } else {
                                 // Direct check
                                 if (keyBytes != null && keyBytes.length == 39) {
                                    String s = new String(keyBytes, StandardCharsets.UTF_8);
                                    if (s.startsWith("DEV")) utils.inspectKey(s, "SecretKeySpec(" + algo + ")");
                                }
                            }
                        } catch (Exception e) {}
                    }
                };
                
                XposedHelpers.findAndHookConstructor("javax.crypto.spec.SecretKeySpec", lpparam.classLoader, byte[].class, String.class, keyHook);
                try { 
                    XposedHelpers.findAndHookConstructor("javax.crypto.spec.SecretKeySpec", lpparam.classLoader, byte[].class, int.class, int.class, String.class, keyHook);
                } catch(Throwable t) {}

            } catch (Throwable t) {
                XposedBridge.log(TAG + " Hook SecretKeySpec Failed: " + t);
            }

            // Mac.init Hook
            try {
                XposedHelpers.findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "init", Key.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            Key key = (Key) param.args[0];
                            if (key != null) {
                                byte[] encoded = key.getEncoded();
                                if (encoded != null) {
                                    String s = new String(encoded, StandardCharsets.UTF_8);
                                    utils.inspectKey(s, "HMAC.init");
                                }
                            }
                        } catch (Exception e) {}
                    }
                });
            } catch (Throwable t) {
                XposedBridge.log(TAG + " Hook Mac Failed: " + t);
            }

            // ================== BODY CAPTURE (Cipher) ==================
            
            // Init Hook (Track Mode)
            final XC_MethodHook cipherInitHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Cipher instance = (Cipher) param.thisObject;
                        int mode = (int) param.args[0];
                        String algo = instance.getAlgorithm();

                        // Log RSA Key
                        if (algo.toUpperCase().contains("RSA")) {
                           XposedBridge.log("\n⚙️ [Cipher Init] " + algo + " [Mode: " + mode + "]");
                           try {
                               XposedBridge.log("   Provider: " + instance.getProvider().getName());
                           } catch (Exception e) {}

                           if (param.args.length > 1 && param.args[1] instanceof Key) {
                               Key key = (Key) param.args[1];
                               if (key != null) {
                                   // Try RSA Specifics
                                   if (key instanceof java.security.interfaces.RSAPublicKey) {
                                       try {
                                           java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) key;
                                           XposedBridge.log("   RSA Modulus: " + pubKey.getModulus().toString(16));
                                           XposedBridge.log("   RSA Exponent: " + pubKey.getPublicExponent().toString(16));
                                       } catch (Exception e) {}
                                   }

                                   byte[] encoded = key.getEncoded();
                                   if (encoded != null) {
                                       String keyB64 = Base64.encodeToString(encoded, Base64.NO_WRAP);
                                       XposedBridge.log("   Key (Base64 X.509): " + keyB64);
                                   }
                               }
                           }
                        }

                        if ((algo.toUpperCase().contains("AES") || algo.toUpperCase().contains("RIJNDAEL")) && mode == Cipher.ENCRYPT_MODE) {
                            cipherModes.put(instance, mode);
                        }
                    } catch (Exception e) {}
                }
            };

            try {
                Class<?> cipherClass = XposedHelpers.findClass("javax.crypto.Cipher", lpparam.classLoader);
                
                // Hook ALL init overloads
                XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, cipherInitHook);
                XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, AlgorithmParameterSpec.class, cipherInitHook);
                XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, java.security.SecureRandom.class, cipherInitHook);
                try { XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, AlgorithmParameterSpec.class, java.security.SecureRandom.class, cipherInitHook); } catch (Throwable t) {}
                try { XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, java.security.AlgorithmParameters.class, cipherInitHook); } catch (Throwable t) {}
                try { XposedHelpers.findAndHookMethod(cipherClass, "init", int.class, Key.class, java.security.AlgorithmParameters.class, java.security.SecureRandom.class, cipherInitHook); } catch (Throwable t) {}
                
                // UNIFIED DoFinal Hook (Checks Input AND Output)
                XC_MethodHook doFinalHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            // 1. Check Input (Plaintext if Encrypting)
                            byte[] inputBytes = null;
                            if (param.args.length == 1 && param.args[0] instanceof byte[]) {
                                 inputBytes = (byte[]) param.args[0];
                            } else if (param.args.length == 3 && param.args[0] instanceof byte[]) {
                                 byte[] buf = (byte[]) param.args[0];
                                 int off = (int) param.args[1];
                                 int len = (int) param.args[2];
                                 if (buf != null && len > 0) {
                                     inputBytes = new byte[len];
                                     System.arraycopy(buf, off, inputBytes, 0, len);
                                 }
                            }
                            if (inputBytes != null) utils.tryParseJson(inputBytes, "Cipher Input");

                            // 2. Check Output (Plaintext if Decrypting)
                            Object res = param.getResult();
                            if (res instanceof byte[]) {
                                utils.tryParseJson((byte[]) res, "Cipher Output");
                            }
                        } catch (Exception e) {}
                    }
                };

                XposedHelpers.findAndHookMethod(cipherClass, "doFinal", byte[].class, doFinalHook);
                try { XposedHelpers.findAndHookMethod(cipherClass, "doFinal", byte[].class, int.class, int.class, doFinalHook); } catch (Throwable t) {}
                
                // UNIFIED Update Hook (Same logic)
                XC_MethodHook updateHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            byte[] inputBytes = null;
                            if (param.args.length >= 1 && param.args[0] instanceof byte[]) {
                                 if (param.args.length >= 3 && param.args[1] instanceof Integer && param.args[2] instanceof Integer) {
                                     byte[] buf = (byte[]) param.args[0];
                                     int off = (int) param.args[1];
                                     int len = (int) param.args[2];
                                     if (buf != null && len > 0) {
                                         inputBytes = new byte[len];
                                         System.arraycopy(buf, off, inputBytes, 0, len);
                                     }
                                 } else {
                                     inputBytes = (byte[]) param.args[0];
                                 }
                            }
                            if (inputBytes != null) utils.tryParseJson(inputBytes, "Cipher.update Input");
                            
                            Object res = param.getResult();
                            if (res instanceof byte[]) {
                                 utils.tryParseJson((byte[]) res, "Cipher.update Output");
                            }
                        } catch (Exception e) {}
                    }
                };
                try { XposedHelpers.findAndHookMethod(cipherClass, "update", byte[].class, updateHook); } catch (Throwable t) {}
                try { XposedHelpers.findAndHookMethod(cipherClass, "update", byte[].class, int.class, int.class, updateHook); } catch (Throwable t) {}

                // NIO Hook
                 XC_MethodHook nioHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                             if (param.args.length >= 1 && param.args[0] instanceof java.nio.ByteBuffer) {
                                 utils.tryParseJson((java.nio.ByteBuffer) param.args[0], "Cipher(NIO) Input");
                             }
                            if (param.args.length >= 2 && param.args[1] instanceof java.nio.ByteBuffer) {
                                 utils.tryParseJson((java.nio.ByteBuffer) param.args[1], "Cipher(NIO) Output");
                            }
                        } catch (Exception e) {}
                    }
                };
                try { XposedHelpers.findAndHookMethod(cipherClass, "doFinal", java.nio.ByteBuffer.class, java.nio.ByteBuffer.class, nioHook); } catch (Throwable t) {}
                try { XposedHelpers.findAndHookMethod(cipherClass, "update", java.nio.ByteBuffer.class, java.nio.ByteBuffer.class, nioHook); } catch (Throwable t) {}


            } catch (Throwable t) {
                XposedBridge.log(TAG + " Hook Cipher Failed: " + t);
            }

            // ================== NETWORK CAPTURE (SSL) ==================
            try {
                Class<?> nativeCrypto = null;
                // Safely look up NativeCrypto
                try { nativeCrypto = XposedHelpers.findClass("com.android.org.conscrypt.NativeCrypto", lpparam.classLoader); } catch(Throwable t) {}
                if (nativeCrypto == null) {
                    try { nativeCrypto = XposedHelpers.findClass("org.conscrypt.NativeCrypto", lpparam.classLoader); } catch(Throwable t) {}
                }

                if (nativeCrypto != null) {
                    XposedBridge.log(TAG + " Found NativeCrypto: " + nativeCrypto.getName());

                    // SSL_write (Request)
                    XposedBridge.hookAllMethods(nativeCrypto, "SSL_write", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                byte[] buf = null;
                                int off = 0;
                                int len = 0;
                                
                                for (Object arg : param.args) {
                                    if (arg instanceof byte[]) { buf = (byte[]) arg; }
                                    else if (arg instanceof Integer) {
                                        if (off == 0) off = (Integer) arg;
                                        else if (len == 0) len = (Integer) arg;
                                    }
                                }
                                
                                // Validation: ensure we don't read out of bounds
                                if (buf != null && len > 0) {
                                     // Safe check for bounds
                                     if (off + len <= buf.length && off >= 0) {
                                         byte[] data = new byte[len];
                                         System.arraycopy(buf, off, data, 0, len);
                                         utils.tryParseHttp(data, "SSL Request");
                                     }
                                }
                            } catch (Exception e) {}
                        }
                    });

                    // SSL_read (Response)
                    XposedBridge.hookAllMethods(nativeCrypto, "SSL_read", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                int amount = (Integer) param.getResult();
                                if (amount > 0) {
                                    byte[] buf = null;
                                    int off = 0;
                                    
                                    for (Object arg : param.args) {
                                        if (arg instanceof byte[]) { buf = (byte[]) arg; }
                                        else if (arg instanceof Integer) {
                                            if (off == 0) off = (Integer) arg;
                                        }
                                    }
                                    
                                    if (buf != null) {
                                        if (off + amount <= buf.length && off >= 0) {
                                            byte[] data = new byte[amount];
                                            System.arraycopy(buf, off, data, 0, amount);
                                            utils.tryParseHttp(data, "SSL Response");
                                        }
                                    }
                                }
                            } catch (Exception e) {}
                        }
                    });
                    XposedBridge.log(TAG + " ✅ Hooked NativeCrypto SSL");
                }
            } catch (Throwable t) {
                XposedBridge.log(TAG + " Hook SSL Failed: " + t);
            }

            // ================== VOLUME KEY LISTENER ==================
            try {
                XposedHelpers.findAndHookMethod(Activity.class, "dispatchKeyEvent", KeyEvent.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        KeyEvent event = (KeyEvent) param.args[0];
                        int keyCode = event.getKeyCode();
                        boolean isDown = event.getAction() == KeyEvent.ACTION_DOWN;
                        
                        if (!isDown) return;

                        // VOLUME UP: Copy Info
                        if (keyCode == KeyEvent.KEYCODE_VOLUME_UP) {
                            try {
                                Activity activity = (Activity) param.thisObject;
                                
                                String jsonStr = CaptureInfo.toJson();
                                XposedBridge.log("\n[+] 📋 Copying to Clipboard: " + jsonStr);

                                ClipboardManager clipboard = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                                ClipData clip = ClipData.newPlainText("CaptureInfo", jsonStr);
                                clipboard.setPrimaryClip(clip);

                                 Toast.makeText(activity, "CaptureInfo Copied!", Toast.LENGTH_SHORT).show();
                                 param.setResult(true); 

                            } catch (Exception e) {}
                        } 
                        // VOLUME DOWN: RESET IDENTITY & CLEAN
                        else if (keyCode == KeyEvent.KEYCODE_VOLUME_DOWN) {
                             try {
                                  Activity activity = (Activity) param.thisObject;
                                  XposedBridge.log("\n[!!!] 🚨 RESETTING IDENTITY & CLEANING STORAGE 🚨");
                                  
                                  Toast.makeText(activity, "Cleaning... Please Wait...", Toast.LENGTH_SHORT).show();

                                  new Thread(() -> {
                                      try {
                                          IdentityManager.generateNew(activity);
                                          StorageCleaner.cleanAll(activity);
                                          
                                          activity.runOnUiThread(() -> 
                                              Toast.makeText(activity, "Done! App will close in 2s...", Toast.LENGTH_SHORT).show()
                                          );
                                          
                                          try { Thread.sleep(2000); } catch (InterruptedException e) {}
                                          
                                          android.os.Process.killProcess(android.os.Process.myPid());
                                          System.exit(0);
                                      } catch (Exception e) {}
                                  }).start();

                                  param.setResult(true);
                             } catch (Exception e) {}
                        }
                    }
                });
                XposedBridge.log("[+] Volume Control Enabled (Up=Copy, Down=Reset)");
            } catch (Throwable t) {
                XposedBridge.log(TAG + " Hook Activity Failed: " + t);
            }
        } catch(Throwable mainT) {
             XposedBridge.log(TAG + " FATAL ERROR in handleLoadPackage: " + mainT);
             mainT.printStackTrace();
        }
    }

    // ================== PROTOCOL HIJACK ==================
    private void hookProtocolHijack(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // Hook 1: Collections.unmodifiableList
            XposedHelpers.findAndHookMethod(Collections.class, "unmodifiableList", java.util.List.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    java.util.List<?> list = (java.util.List<?>) param.args[0];
                    if (list == null || list.isEmpty()) return;

                    // Fast check 1st element
                    try {
                        Object first = list.get(0);
                        if (first == null) return;
                        String str = first.toString();
                        // Check for Protocol Enums
                        if (isProtocolString(str)) {
                            // Scan for H2
                            boolean hasH2 = false;
                            Object h2Enum = null;
                            for (Object o : list) {
                                String s = o.toString();
                                if ("h2".equals(s) || "h2_prior_knowledge".equals(s)) {
                                    hasH2 = true;
                                    h2Enum = o;
                                    break;
                                }
                            }

                            if (hasH2 && h2Enum != null) {
                                XposedBridge.log(TAG + " [Hijack] ☢️ Detonating H2 in unmodifiableList!");
                                Object http11 = findHttp11Enum(h2Enum);
                                if (http11 != null) {
                                    // create new list with just HTTP/1.1
                                    java.util.List<Object> newList = new java.util.ArrayList<>();
                                    newList.add(http11);
                                    param.args[0] = newList;
                                    XposedBridge.log(TAG + " [Hijack] -> Replaced with HTTP/1.1");
                                }
                            }
                        }
                    } catch (Exception e) {}
                }
            });

            // Hook 2: Arrays.asList
            XposedHelpers.findAndHookMethod(java.util.Arrays.class, "asList", Object[].class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object[] arr = (Object[]) param.args[0];
                    if (arr == null || arr.length == 0) return;

                    try {
                        Object first = arr[0];
                        if (first == null) return;
                        String str = first.toString();
                        if (isProtocolString(str)) {
                            boolean hasH2 = false;
                            Object h2Enum = null;
                            for (Object o : arr) {
                                String s = o.toString();
                                if ("h2".equals(s) || "h2_prior_knowledge".equals(s)) {
                                    hasH2 = true;
                                    h2Enum = o;
                                    break;
                                }
                            }

                            if (hasH2 && h2Enum != null) {
                                XposedBridge.log(TAG + " [Hijack] ☢️ Detonating H2 in Arrays.asList!");
                                Object http11 = findHttp11Enum(h2Enum);
                                if (http11 != null) {
                                    // Create new array of same type
                                    Object[] newArr = (Object[]) java.lang.reflect.Array.newInstance(h2Enum.getClass(), 1);
                                    newArr[0] = http11;
                                    param.args[0] = newArr;
                                    XposedBridge.log(TAG + " [Hijack] -> Replaced with HTTP/1.1");
                                }
                            }
                        }
                    } catch (Exception e) {}
                }
            });
            XposedBridge.log("[+] Protocol Hijacking Active (H2 -> HTTP/1.1)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Hijack Hook Failed: " + t);
        }
    }

    private boolean isProtocolString(String s) {
        return "h2".equals(s) || "http/1.1".equals(s) || "spdy/3.1".equals(s) || "h2_prior_knowledge".equals(s) || "HTTP_1_1".equals(s);
    }

    private Object findHttp11Enum(Object h2Enum) {
        try {
            Class<?> enumClass = h2Enum.getClass();
            for (Object f : enumClass.getEnumConstants()) {
                String s = f.toString();
                if ("http/1.1".equals(s) || "HTTP_1_1".equals(s)) return f;
            }
        } catch (Exception e) {}
        return null;
    }

    // ================== HASH FUNCTION HOOKS ==================
    private void hookHashFunctions(XC_LoadPackage.LoadPackageParam lpparam, final Object utilsObj) {
        try {
            // Reflection cast to access tryParseHttp helper
            final java.lang.reflect.Method tryParseHttp = utilsObj.getClass().getDeclaredMethod("tryParseHttp", byte[].class, String.class);
            tryParseHttp.setAccessible(true);
            
            Class<?> hashClass = XposedHelpers.findClass("f.l.a.m.i", lpparam.classLoader);
            XposedBridge.hookAllMethods(hashClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("\n🎯 [f.l.a.m.i.a] Called with " + param.args.length + " args");
                    for (int i = 0; i < param.args.length; i++) {
                        Object arg = param.args[i];
                        if (arg instanceof byte[]) {
                            byte[] b = (byte[]) arg;
                             String b64 = Base64.encodeToString(b, Base64.NO_WRAP);
                             XposedBridge.log("   Arg[" + i + "] (B64): " + b64);
                             try { tryParseHttp.invoke(utilsObj, b, "Arg["+i+"] SafeView"); } catch(Exception e) {}
                        } else if (arg instanceof String) {
                             XposedBridge.log("   Arg[" + i + "] (Str): " + arg);
                        } else {
                             String val = (arg != null) ? arg.toString() : "null";
                             XposedBridge.log("   Arg[" + i + "]: " + val);
                        }
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof byte[]) {
                        byte[] b = (byte[]) res;
                        String b64 = Base64.encodeToString(b, Base64.NO_WRAP);
                        XposedBridge.log("   Ret (B64): " + b64);
                    } else if (res != null) {
                         XposedBridge.log("   Ret: " + res.toString());
                    }
                }
            });
            XposedBridge.log("[+] Hooked f.l.a.m.i.a (Hash Function)");
        } catch (Throwable t) {
            XposedBridge.log(TAG + " Hash Hook Failed (f.l.a.m.i): " + t);
        }
        }
        // ================== FULL HTTP LOGGING ==================
    private void hookFullHttpLogging(XC_LoadPackage.LoadPackageParam lpparam, final Object utilsObj) {
        try {
            // Helper Method Ref
            final java.lang.reflect.Method tryParseJson = utilsObj.getClass().getDeclaredMethod("tryParseJson", byte[].class, String.class);
            tryParseJson.setAccessible(true);

            // 1. Response Body Decompression (GZIP)
            // Hook: java.util.zip.GZIPInputStream.read(byte[], int, int)
            XposedBridge.hookAllMethods(java.util.zip.GZIPInputStream.class, "read", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    int ret = (Integer) param.getResult();
                    if (ret > 0) {
                        try {
                            byte[] buffer = null;
                            if (param.args.length >= 1 && param.args[0] instanceof byte[]) {
                                buffer = (byte[]) param.args[0];
                                int off = (param.args.length >= 2) ? (Integer) param.args[1] : 0;
                                int len = ret; // bytes read
                                
                                if (buffer != null && len > 0) {
                                    byte[] data = new byte[len];
                                    System.arraycopy(buffer, off, data, 0, len);
                                    tryParseJson.invoke(utilsObj, data, "GZIP Response Body");
                                }
                            }
                        } catch (Exception e) {}
                    }
                }
            });

            // 2. Response Body Decompression (Inflater - Raw)
            XposedHelpers.findAndHookMethod(java.util.zip.Inflater.class, "inflate", byte[].class, int.class, int.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    int ret = (Integer) param.getResult();
                    if (ret > 0) {
                         try {
                             byte[] buffer = (byte[]) param.args[0];
                             int off = (Integer) param.args[1];
                             int len = ret;
                             if (buffer != null && len > 0) {
                                  byte[] data = new byte[len];
                                  System.arraycopy(buffer, off, data, 0, len);
                                  tryParseJson.invoke(utilsObj, data, "Inflater Response Body");
                             }
                        } catch (Exception e) {}
                    }
                }
            });

            // 3. OkHttp Request (o.a0) - Obfuscated Class
            try {
                Class<?> clientClass = XposedHelpers.findClass("o.a0", lpparam.classLoader);
                // Hook all methods to dump args (Requests)
                XposedBridge.hookAllMethods(clientClass, "a", new XC_MethodHook() {
                     @Override
                     protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                         XposedBridge.log("\n🚀 [OkHttp o.a0] Called: " + param.method.getName());
                         for(int i=0; i<param.args.length; i++) {
                             Object arg = param.args[i];
                             String val = (arg != null) ? arg.toString() : "null";
                             XposedBridge.log("   Arg[" + i + "]: " + val);
                             
                             // If it looks like a Request, try to inspect it
                             if (val.contains("Request{")) {
                                  // Dump Headers/Url?
                             }
                         }
                     }
                });
            } catch (Throwable t) {
                // Class likely not found or renamed
                // XposedBridge.log(TAG + " OkHttp Hook (o.a0) Missing: " + t);
            }

            XposedBridge.log("[+] Full HTTP Logging (GZIP/Inflater) Active");

        } catch (Throwable t) {
            XposedBridge.log(TAG + " HTTP Logging Hook Failed: " + t);
        }
    }
}
