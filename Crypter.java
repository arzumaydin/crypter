package com.crypter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Component
public class Crypter {

    private static final String algorithm = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 16;
    private static String key;

    @Autowired
    public Crypter(@Value("${backend.encryption.key}") String key) {
        Crypter.key = key;
    }

    private static SecretKeySpec getSecretKey() {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(String input) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        byte[] iv = generateIv();
        SecretKey secretKey = getSecretKey();
        GCMParameterSpec ivSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] cipherText = cipher.doFinal(input.getBytes());

        byte[] ivCTAndTag = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, ivCTAndTag, 0, iv.length);
        System.arraycopy(cipherText, 0, ivCTAndTag, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(ivCTAndTag);
    }

    public static String decrypt(String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        SecretKey secretKey = getSecretKey();
        Cipher cipher = Cipher.getInstance(algorithm);
        byte[] decodedToDecrypt = Base64.getDecoder().decode(cipherText);
        byte[] iv  = new byte[IV_LENGTH_BYTE];

        System.arraycopy(decodedToDecrypt, 0, iv, 0, iv.length);
        GCMParameterSpec ivSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        byte[] encryptedBytes = new byte[decodedToDecrypt.length - iv.length];
        System.arraycopy(decodedToDecrypt, iv.length, encryptedBytes, 0, encryptedBytes.length);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] plainText = cipher.doFinal(encryptedBytes);

        return new String(plainText);
    }
}
