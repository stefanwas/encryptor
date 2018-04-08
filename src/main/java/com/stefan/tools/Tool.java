package com.stefan.tools;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class Tool {

    public static void main(String[] args) throws Exception {

        encrypt();
//        decrypt();

    }

    private static void decrypt() throws Exception {

        // 1. read private key
        PrivateKey privateKey = KeyUtil.readRSAPrivateKeyFromFile(new File("keys/rsa-private.key"));
        System.out.println("PrivateKey length=" + privateKey.getEncoded().length);

        // 2. read encrypted file content
        byte[] encryptedContent = Files.readAllBytes(new File("samples/test.txt-encrypted").toPath());

        // 3. split content to AES key & payload
        byte[] encryptedSecretKey = Arrays.copyOf(encryptedContent, 64); // 512 bits = RSA key size
        byte[] encryptedPayload = Arrays.copyOfRange(encryptedContent, 64, encryptedContent.length);

        // 4. decrypt AES key with private RSA key
        byte[] decryptedSecretKeyBytes = EncryptionUtil.decrypt(encryptedSecretKey, privateKey);
        SecretKey secretKey = KeyUtil.createAESSecretKey(decryptedSecretKeyBytes);

        // 5. decrypt payload with AES key
        byte[] decryptedPayload = EncryptionUtil.decrypt(encryptedPayload, secretKey);

        // 6. save decrypted payload to file
        Files.write(new File("samples/test.txt-decrypted").toPath(), decryptedPayload, StandardOpenOption.CREATE);

    }

    private static void encrypt() throws Exception {
        // 1. read public key
        PublicKey publicKey = KeyUtil.readRSAPublicKeyFromFile(new File("keys/rsa-public.key"));
        System.out.println("PublicKey length=" + publicKey.getEncoded().length);

        // 2. generate symmetric key
        SecretKey secretKey = EncryptionUtil.generateAESKey(128);
        System.out.println("SecretKey length=" + secretKey.getEncoded().length);

        // 3. read input file
        byte[] payload = Files.readAllBytes(new File("samples/test.txt").toPath());
        System.out.println("Original payload length=" + payload.length);

        // 4. encrypt content with symmetric key
        byte[] encryptedPayload = EncryptionUtil.encrypt(payload, secretKey);
        System.out.println("Encrypted payload length=" + encryptedPayload.length);

        // 5. encrypt symmetric key with public key
        byte[] encryptedSecretKey = EncryptionUtil.encrypt(secretKey.getEncoded(), publicKey);
        System.out.println("Encrypted SecretKey length=" + encryptedSecretKey.length);

        // 6. merge encrypted content & encrypted symmetric key
        byte[] encryptedContent = new byte[encryptedSecretKey.length + encryptedPayload.length];
        System.arraycopy(encryptedSecretKey, 0, encryptedContent, 0, encryptedSecretKey.length);
        System.arraycopy(encryptedPayload, 0, encryptedContent, encryptedSecretKey.length, encryptedPayload.length);

        // 7. save it to file
        Files.write(new File("samples/test.txt-encrypted").toPath(), encryptedContent, StandardOpenOption.CREATE);
    }
}
