package com.stefan.tools;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricKeyEncryption {

    private static KeyFactory KEY_FACTORY;

    static {
        try {
            KEY_FACTORY = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void encryptFile(String fileName, String privateKeyFile) throws Exception {
        String privateKey = FileUtils.readKeyFromFile(privateKeyFile);
        byte[] content = Files.readAllBytes(new File(fileName).toPath());
        byte[] encryptedContent = encrypt(content, createPrivateKey(privateKey));
        Files.write(new File(fileName + ".encrypted").toPath(), encryptedContent, StandardOpenOption.CREATE_NEW);
    }

    public static void decryptFile(String fileName, String publicKeyFile) throws Exception {
        String publicKey = FileUtils.readKeyFromFile(publicKeyFile);
        byte[] content = Files.readAllBytes(new File(fileName).toPath());
        byte[] decryptedContent = decrypt(content, createPublicKey(publicKey));
        Files.write(new File(fileName + ".decrypted").toPath(), decryptedContent, StandardOpenOption.CREATE_NEW);
    }


    public static byte[] encrypt(byte[] content, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(content);

    }

    public static byte[] decrypt(byte[] encryptedContent, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedContent);
    }



    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    private static PrivateKey createPrivateKey(String privateKey) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return KEY_FACTORY.generatePrivate(spec);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    private static PublicKey createPublicKey(String publicKey) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        return KEY_FACTORY.generatePublic(spec);
    }

    public static void main(String[] args) throws Exception {
        encryptFile("test.txt", "rsa-key.public");
        decryptFile("test.txt.encrypted", "rsa-key.private");
    }



}
