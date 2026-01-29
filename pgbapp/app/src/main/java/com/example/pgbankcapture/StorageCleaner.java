package com.example.pgbankcapture;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.security.KeyStore;

import de.robv.android.xposed.XposedBridge;

public class StorageCleaner {

    private static final String TARGET_KEY_ALIAS = "APP_PGB_2";

    public static void cleanAll(Context context) {
        XposedBridge.log("PgbankCleaner: Starting full cleanup...");
        
        // 1. Clean KeyStore
        cleanKeyStore();
        
        // 2. Clean App Files (SharedPrefs, Databases, Cache)
        cleanAppStorage(context);
        
        XposedBridge.log("PgbankCleaner: Cleanup complete.");
    }

    private static void cleanKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            
            if (ks.containsAlias(TARGET_KEY_ALIAS)) {
                ks.deleteEntry(TARGET_KEY_ALIAS);
                XposedBridge.log("PgbankCleaner: [✔] Deleted KeyStore alias: " + TARGET_KEY_ALIAS);
            } else {
                XposedBridge.log("PgbankCleaner: [-] KeyStore alias not found: " + TARGET_KEY_ALIAS);
            }
        } catch (Exception e) {
            XposedBridge.log("PgbankCleaner: [x] KeyStore error: " + e);
        }
    }

    private static void cleanAppStorage(Context context) {
        try {
            File rootDir = context.getFilesDir().getParentFile();
            if (rootDir != null && rootDir.exists()) {
                String[] targets = {"shared_prefs", "databases", "cache", "code_cache", "files"};
                for (String target : targets) {
                    File dir = new File(rootDir, target);
                    if (dir.exists()) {
                        deleteRecursive(dir, target.equals("shared_prefs")); 
                        // Note: For shared_prefs, we might want to KEEP our identity pref if it's there?
                        // If IdentityManager uses "identity_spoof", we should preserve it.
                    }
                }
            }
        } catch (Exception e) {
            XposedBridge.log("PgbankCleaner: [x] Storage error: " + e);
        }
    }

    private static void deleteRecursive(File fileOrDir, boolean checkIdentity) {
        if (fileOrDir.isDirectory()) {
            for (File child : fileOrDir.listFiles()) {
                deleteRecursive(child, checkIdentity);
            }
        }
        
        // Don't delete our spoof config!
        if (checkIdentity && fileOrDir.getName().contains("identity_spoof")) {
            XposedBridge.log("PgbankCleaner: Preserving identity file: " + fileOrDir.getName());
            return;
        }

        fileOrDir.delete();
    }
}
