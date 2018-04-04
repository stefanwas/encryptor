package com.stefan.tools;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.security.*;

public class AsymmetricKeyGenerator {


    public static void createRSAKeys(int keyLength) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair pair = generateRSAKeyPair(keyLength);

//        String privateKeyFormat = pair.getPrivate().getFormat();
//        System.out.println("PRIVATE FORMAT:" + privateKeyFormat);   // -> PKCS#8
//
//        String publicKeyFormat = pair.getPublic().getFormat();
//        System.out.println("PUBLIC FORMAT:" + publicKeyFormat);     // -> X.509


        String privateKey = Base64.encodeBase64String(pair.getPrivate().getEncoded());
        String publicKey = Base64.encodeBase64String(pair.getPublic().getEncoded());

        FileUtils.writeKeyToFile(privateKey, "rsa-key.private");
        FileUtils.writeKeyToFile(publicKey, "rsa-key.public");
    }

    public static void saveKeysToFile(KeyPair keyPair, String fileName) {
        String privateKey = Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
        String publicKey = Base64.encodeBase64String(keyPair.getPublic().getEncoded());

        FileUtils.writeKeyToFile(privateKey, fileName + ".private");
        FileUtils.writeKeyToFile(publicKey, fileName + ".pubic");
    }

    public static KeyPair generateRSAKeyPair(int keyLength) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        return keyPairGenerator.generateKeyPair();
    }

    // symmetric key generator

//    KeyGenerator generator = KeyGenerator.getInstance("AES");
//    generator.init(128); // The AES key size in number of bits
//    SecretKey secKey = generator.generateKey();
//
        // thow to encrypt ...
//    String plainText = "Please encrypt me urgently..."
//    Cipher aesCipher = Cipher.getInstance("AES");
//    aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
//    byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());



    public static void main(String[] args) throws Exception {
        createRSAKeys(512);
    }


}
