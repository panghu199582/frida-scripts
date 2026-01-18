package com.example.pvcbbankcapture;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CaptureInfo {
    private static final Map<String, String> data = new ConcurrentHashMap<>();

    static {
        // Init with empty or generic
    }

    public static void update(String key, String value) {
        if (value != null && !value.isEmpty()) {
            data.put(key, value);
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
}
