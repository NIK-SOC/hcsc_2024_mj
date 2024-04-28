package hu.honeylab.hcsc.thereott;

public class UtilsJNI {
    static {
        System.loadLibrary("antiskid");
    }

    public static native String genSignature(String method, String path, String responseStatus, String headers, String body, String timestamp);
}

