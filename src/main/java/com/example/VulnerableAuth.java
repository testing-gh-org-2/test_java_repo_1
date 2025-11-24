package com.example;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

/**
 * Authentication class with cryptographic vulnerabilities
 */
public class VulnerableAuth {
    
    // Hardcoded encryption key (CWE-321)
    private static final String SECRET_KEY = "MySecretKey12345";
    
    // Weak encryption algorithm (CWE-327)
    public static String encryptData(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES"); // Vulnerable: DES is weak
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    // ECB mode encryption (CWE-326)
    public static String encryptWithAES(String data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Vulnerable: ECB mode
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    // Weak hash for password storage (CWE-916)
    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1"); // Vulnerable: SHA1 is weak
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    // Insecure random for cryptographic purposes (CWE-338)
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new java.util.Random().nextBytes(iv); // Vulnerable: not cryptographically secure
        return iv;
    }
    
    // Static IV for encryption (CWE-329)
    private static final byte[] STATIC_IV = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    public static String encryptWithStaticIV(String data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(STATIC_IV); // Vulnerable: static IV
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    // Improper certificate validation
    public static void disableSSLValidation() throws Exception {
        // Vulnerable: disables SSL certificate validation
        TrustManager[] trustAllCerts = new TrustManager[] {
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };
        
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
}
