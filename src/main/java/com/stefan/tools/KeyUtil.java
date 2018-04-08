package com.stefan.tools;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtil {

    public static void saveKeyToFile(Key key, File file) throws IOException {
        String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
        FileUtil.saveToFile(keyString, file);
    }

    public static PublicKey readRSAPublicKeyFromFile(File file) throws Exception {
        String publicKeyString = FileUtil.readFromFile(file);
        PublicKey publicKey = createRSAPublicKey(publicKeyString);
        return publicKey;
    }

    public static PrivateKey readRSAPrivateKeyFromFile(File file) throws Exception {
        String privateKeyString = FileUtil.readFromFile(file);
        PrivateKey privateKey = createRSAPrivateKey(privateKeyString);
        return privateKey;
    }

    public static SecretKey readAESKeyFromFile(File file) throws Exception {
        String privateKeyString = FileUtil.readFromFile(file);
        SecretKey secretKey = createAESSecretKey(privateKeyString);
        return secretKey;
    }

    public static SecretKey createAESSecretKey(byte[] secretKeyBytes) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");
        return secretKeySpec;
    }

    static SecretKey createAESSecretKey(String secretKey) throws Exception {
        byte[] secretKeyBytes = Base64.getDecoder().decode(secretKey);
        return createAESSecretKey(secretKeyBytes);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    private static PrivateKey createRSAPrivateKey(String privateKey) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    private static PublicKey createRSAPublicKey(String publicKey) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }





}
