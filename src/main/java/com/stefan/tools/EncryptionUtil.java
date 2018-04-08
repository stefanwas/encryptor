package com.stefan.tools;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class EncryptionUtil {

    public static byte[] encrypt(byte[] content, Key key) throws Exception {
        Cipher aesCipher = Cipher.getInstance(key.getAlgorithm());
        aesCipher.init(Cipher.ENCRYPT_MODE, key);
        return aesCipher.doFinal(content);
    }

    public static byte[] decrypt(byte[] content, Key key) throws Exception {
        Cipher aesCipher = Cipher.getInstance(key.getAlgorithm());
        aesCipher.init(Cipher.DECRYPT_MODE, key);
        return aesCipher.doFinal(content);
    }

    public static KeyPair generateRSAKeyPair(int keyLength) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey generateAESKey(int keyLength) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(keyLength); // The AES key size in number of bits
        return generator.generateKey();
    }





    public static void main(String[] args) throws Exception {

//        SecretKey secretKey = generateAESKey(128); //128 bits = 16 bytes
//
//
//        byte[] secretKeyBytes = secretKey.getEncoded();
//
//        System.out.println("AES key length=" + secretKeyBytes.length);  //16 bytes
//
//        String publicKeyStr = FileUtil.readFromFile(new F"keys/rsa-key.public");
//        PublicKey publicKey = createRSAPublicKey(publicKeyStr);
//
//        byte[] encryptedAesKeyBytes = encrypt(secretKeyBytes, publicKey);
//        System.out.println("Encrypted AES key length=" + encryptedAesKeyBytes.length); //64bytes (same as public key length 512 bits)

//        encryptFile2("samples/test.txt", "keys/rsa-key.public");
//        decryptFile2("samples/test.txt.encrypted", "keys/rsa-key.private");
    }



}
