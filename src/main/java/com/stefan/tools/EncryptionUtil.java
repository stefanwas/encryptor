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

}
