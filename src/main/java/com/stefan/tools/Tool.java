package com.stefan.tools;

import org.apache.commons.io.IOUtils;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static java.nio.file.StandardOpenOption.CREATE;

public class Tool {

    public static final String PUBLIC_KEY_FILE = "RSA2048_public.key";
    public static final String PRIVATE_KEY_FILE = "RSA2048_private.key";

    public static final int RSA_KEY_SIZE_BITS = 2048;   // asymmetric encryption - used to encrypt small content (here aes key)
    public static final int AES_KEY_SIZE_BITS = 128;    // symmetric encryption - to encrypt the payload

    public static void main(String[] args) throws Exception {


        if (args.length != 2) {
            System.err.println("Invalid args! Usage <program> [encrypt|decrypt] <file_name>");
            System.exit(1);
        }

        String action  = args[0].toLowerCase();
        String inputFileName = args[1];

        if (action.equals("encrypt") || action.equals("e")) {
            System.out.println("Encrypting file: " + inputFileName);

            String publicKeyBase64 = IOUtils.toString(
                    Tool.class.getClassLoader().getResourceAsStream(PUBLIC_KEY_FILE), Charset.forName("UTF-8"));
            PublicKey rsaPublicKey = KeyUtil.createRSAPublicKey(publicKeyBase64);

            encrypt(inputFileName, rsaPublicKey);

            System.out.println("Encrypted and save as: " + inputFileName + "-encrypted");
            System.exit(0);
        }

        if (action.equals("decrypt") || action.equals("d")) {
            System.out.println("Decrypting file: " + inputFileName);

            String privateKeyFile = System.getProperty("key");
            PrivateKey rsaPrivateKey = KeyUtil.readRSAPrivateKeyFromFile(new File(privateKeyFile));

            decrypt(inputFileName, rsaPrivateKey);

            System.out.println("Decrypted and saved as: " + inputFileName + "-decrypted");
            System.exit(0);
        }


//        encrypt();
//        decrypt();
//        generateRSAKeys();
    }

    /* this method is used to generate files with asymmetric RSA keys. */
    private static void generateRSAKeys() throws Exception {
        System.out.println("Generating asymmetric RSA keys...");
        KeyPair keyPair = EncryptionUtil.generateRSAKeyPair(RSA_KEY_SIZE_BITS);

        File privateKeyFile = new File("keys/" + PRIVATE_KEY_FILE);
        KeyUtil.saveKeyToFile(keyPair.getPrivate(), privateKeyFile);
        System.out.println("Saved private key to: " + privateKeyFile.getName());

        File publicKeyFile = new File("keys/" + PUBLIC_KEY_FILE);
        KeyUtil.saveKeyToFile(keyPair.getPublic(), publicKeyFile);
        System.out.println("Saved public key to: " + publicKeyFile.getName());

    }

    private static void decrypt(String inputFileName, PrivateKey privateKey) throws Exception {

        // 1. read private key
//        PrivateKey privateKey = KeyUtil.readRSAPrivateKeyFromFile(new File("keys/rsa-private.key"));
        System.out.println("PrivateKey length=" + privateKey.getEncoded().length);

        // 2. read encrypted file content
        byte[] encryptedContent = Files.readAllBytes(new File(inputFileName).toPath());

        // 3. split content to AES key & payload
        byte[] encryptedSecretKey = Arrays.copyOf(encryptedContent, RSA_KEY_SIZE_BITS / 8); // RSA key size in bytes
        byte[] encryptedPayload = Arrays.copyOfRange(encryptedContent, RSA_KEY_SIZE_BITS / 8, encryptedContent.length);

        // 4. decrypt AES key with private RSA key
        byte[] decryptedSecretKeyBytes = EncryptionUtil.decrypt(encryptedSecretKey, privateKey);
        SecretKey secretKey = KeyUtil.createAESSecretKey(decryptedSecretKeyBytes);

        // 5. decrypt payload with AES key
        byte[] decryptedPayload = EncryptionUtil.decrypt(encryptedPayload, secretKey);

        // 6. save decrypted payload to file
        Files.write(new File(inputFileName + "-decrypted").toPath(), decryptedPayload, CREATE);

    }

    private static void encrypt(String inputFileName, PublicKey publicKey) throws Exception {
        // 1. read public key
//        PublicKey publicKey = KeyUtil.readRSAPublicKeyFromFile(new File("keys/rsa-public.key"));
        System.out.println("PublicKey length=" + publicKey.getEncoded().length);

        // 2. generate symmetric key
        SecretKey secretKey = EncryptionUtil.generateAESKey(AES_KEY_SIZE_BITS);
        System.out.println("SecretKey length=" + secretKey.getEncoded().length);

        // 3. read input file
        byte[] payload = Files.readAllBytes(new File(inputFileName).toPath());
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
        Files.write(new File(inputFileName + "-encrypted").toPath(), encryptedContent, CREATE);
    }
}
