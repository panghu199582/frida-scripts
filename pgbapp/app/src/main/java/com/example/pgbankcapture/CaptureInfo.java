package com.example.pgbankcapture;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;

public class CaptureInfo {
    private static final Map<String, String> data = new ConcurrentHashMap<>();
    private static final Set<String> foundKeys = new HashSet<>();

    static {
        // Defaults
        data.put("appName", "MOBILE");
        data.put("deviceName", "Pixel 4");
        data.put("version", "3.2.9");
        data.put("aesIV", "7f1b041c7586c6ba094c913725eeb039");
    }

    public static void update(String key, String value) {
        if (value != null && !value.isEmpty()) {
            data.put(key, value);
            // Derive UniqueDeviceId
            if ("clientDeviceID".equals(key)) {
                data.put("UniqueDeviceId", value);
            }
        }
    }

    public static String toJson() {
        JSONObject json = new JSONObject(data);
        try {
            return json.toString(2); // Indent 2
        } catch (JSONException e) {
            return "{}";
        }
    }

    public static synchronized boolean addFoundKey(String key) {
        return foundKeys.add(key);
    }
    
    public static Map<String, String> getData() {
        return data;
    }
}
