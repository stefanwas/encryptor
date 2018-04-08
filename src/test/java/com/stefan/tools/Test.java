package com.stefan.tools;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;

public class Test {

    public static void main(String[] args) throws Exception {
        test2();


    }

    private static void test2() throws Exception {
        KeyPair keyPair = EncryptionUtil.generateRSAKeyPair(512);
        System.out.println("KEY PAIR=" + keyPair.toString());
        System.out.println("-----");
        System.out.println("PUB_FORMAT=" + keyPair.getPublic().getFormat());
        System.out.println("PUB_LENGTH=" + keyPair.getPublic().getEncoded().length);
        System.out.println("PUB_ALGRTH=" + keyPair.getPublic().getAlgorithm());
        System.out.println("-----");
        System.out.println("PRV_FORMAT=" + keyPair.getPrivate().getFormat());
        System.out.println("PRV_LENGTH=" + keyPair.getPrivate().getEncoded().length);
        System.out.println("PRV_ALGRTH=" + keyPair.getPrivate().getAlgorithm());
    }

    private static void test1() throws Exception {
        String text = "Ala ma kota";
        KeyPair keyPair = EncryptionUtil.generateRSAKeyPair(512);
        SecretKey secretKey = EncryptionUtil.generateAESKey(128);
        byte[] encryptedText = EncryptionUtil.encrypt(text.getBytes(), keyPair.getPublic());
//        byte[] encryptedText = EncryptionUtil.encrypt(text.getBytes(), secretKey);
        byte[] decryptedText = EncryptionUtil.decrypt(encryptedText, keyPair.getPrivate());
//        byte[] decryptedText = EncryptionUtil.decrypt(encryptedText, secretKey);

        String result = new String(decryptedText);

        System.out.println("RES=" + result);
    }


    //    public static PublicKey readPublicKey(String fileName) throws Exception {
//        String content = readFromFile(new File(fileName + ".public"));
//        PublicKey publicKey = EncryptionUtil.createPublicKey(content);
//        return publicKey;
//    }
//
//    public static PrivateKey readPrivateKey(String fileName) throws Exception {
//        String content = readFromFile(new File(fileName + ".private"));
//        PrivateKey privateKey = EncryptionUtil.createPrivateKey(content);
//        return privateKey;
//    }

//    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
//    private static PublicKey createPublicKey(String publicKey) throws Exception {
//        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
//        return KeyFactory.getInstance("RSA").generatePublic(spec);
//    }
//
//    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
//    private static PrivateKey createPrivateKey(String privateKey) throws Exception {
//        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
//        return KeyFactory.getInstance("RSA").generatePrivate(spec);
//    }

//    public static void saveKeyPairToFiles(KeyPair keyPair, String fileName) throws IOException {
//        String privateKey = org.apache.commons.codec.binary.Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
//        String publicKey = org.apache.commons.codec.binary.Base64.encodeBase64String(keyPair.getPublic().getEncoded());
//
//        saveToFile(privateKey, new File(fileName + ".private"));
//        saveToFile(publicKey, new File(fileName + ".pubic"));
//    }



//    public static void encryptFile(String fileName, String privateKeyFile) throws Exception {
//        String privateKey = FileUtil.readKeyFromFile(privateKeyFile);
//        byte[] content = Files.readAllBytes(new File(fileName).toPath());
//        byte[] encryptedContent = encrypt(content, createRSAPrivateKey(privateKey));
//        Files.write(new File(fileName + ".encrypted").toPath(), encryptedContent, StandardOpenOption.CREATE_NEW);
//    }
//
//    public static void encryptFile2(String fileName, String publicKeyFile) throws Exception {
//        String publicKey = FileUtil.readKeyFromFile(publicKeyFile);
//        byte[] content = Files.readAllBytes(new File(fileName).toPath());
//        byte[] encryptedContent = encrypt(content, createRSAPublicKey(publicKey));
//        Files.write(new File(fileName + ".encrypted").toPath(), encryptedContent, StandardOpenOption.CREATE_NEW);
//    }
//
//    public static void decryptFile(String fileName, String publicKeyFile) throws Exception {
//        String publicKey = FileUtil.readKeyFromFile(publicKeyFile);
//        byte[] content = Files.readAllBytes(new File(fileName).toPath());
//        byte[] decryptedContent = decrypt(content, createRSAPublicKey(publicKey));
//        Files.write(new File(fileName + ".decrypted").toPath(), decryptedContent, StandardOpenOption.CREATE_NEW);
//    }
//
//    public static void decryptFile2(String fileName, String privateKeyFile) throws Exception {
//        String privateKey = FileUtil.readKeyFromFile(privateKeyFile);
//        byte[] content = Files.readAllBytes(new File(fileName).toPath());
//        byte[] decryptedContent = decrypt(content, createRSAPrivateKey(privateKey));
//        Files.write(new File(fileName + ".decrypted").toPath(), decryptedContent, StandardOpenOption.CREATE_NEW);
//    }


//    public static byte[] encrypt(byte[] content, PrivateKey privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
//        return cipher.doFinal(content);
//    }
//
//    public static byte[] encrypt2(byte[] content, PublicKey publicKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return cipher.doFinal(content);
//    }
//
//    public static byte[] decrypt(byte[] encryptedContent, PublicKey publicKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, publicKey);
//        return cipher.doFinal(encryptedContent);
//    }
//
//    public static byte[] decrypt2(byte[] encryptedContent, PrivateKey privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        return cipher.doFinal(encryptedContent);
//    }
}
