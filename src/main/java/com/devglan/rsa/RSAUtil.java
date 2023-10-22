package com.devglan.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {

    private static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzhkHrcYDwU9fdYWsO8YhcWu0ja48ePrZ9+baRl5mpfl6akUk0vzMX9EeV55afF2X0ilP/BbDx/s7tvoK+3Yg52jwwtnqELdXjibOkJVZYd20ilt+cxT3CJhaoKv0qaWFWctv6tPTl1xS5//BcySCP7nfOCjRnZHv9l+gPP0TxHFXpThs4ki9vDohAOTWNvesutiSh/5NDWBoTOFBQaqNlW53wFE/VioafnAVa63Ahz+SH2JhCJwZsTp5+/ulUF+twPj5ncolycYoLaXDCg7dSePbz63qgVFMipwhkTPWHZGpQbfgKb7bUhPMJOXwKUuAVRRNNh32FmuLIpHAZyizYQIDAQAB";
    private static String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOGQetxgPBT191haw7xiFxa7SNrjx4+tn35tpGXmal+XpqRSTS/Mxf0R5Xnlp8XZfSKU/8FsPH+zu2+gr7diDnaPDC2eoQt1eOJs6QlVlh3bSKW35zFPcImFqgq/SppYVZy2/q09OXXFLn/8FzJII/ud84KNGdke/2X6A8/RPEcVelOGziSL28OiEA5NY296y62JKH/k0NYGhM4UFBqo2VbnfAUT9WKhp+cBVrrcCHP5IfYmEInBmxOnn7+6VQX63A+PmdyiXJxigtpcMKDt1J49vPreqBUUyKnCGRM9YdkalBt+ApvttSE8wk5fApS4BVFE02HfYWa4sikcBnKLNhAgMBAAECggEADOXxHpV9Z6w1f6/hcw43ypbggltsqm+ck5CtiWjgCLQfzqXMI64xhi+atAYTiKP82+i8+jxcfVgCSTXF2S3v6judkbw8k1Y+EwXnuJG4OdE7usr2E3K08SNDzLlmQvW6bj+2nd4q6FadU6qkazXWNvHFgAjB8ZgQCf27FAYMpicK5rnTP8tFUPkKmdmCiVvEazeDtVVgwGoEO4KpIvyJdbST8PEg2bweXZuYnCvPABJoaKEvBCHQvsX6Ln2KmoE5z+gNiZ+QoOe8LV50fdjRGzGZazQ/AS3giuykam6iDqfnSosDTKax23936YoUIXIBudY6vDyHLsCPw4eTeFiDLwKBgQDSmbrHFepk2Kj4LPTACBNT65Fp+PQ/lVMNMqG2nJUdM0F35U4ufoeVtShJs3s1mxu+LI3C867UWLMkoMqv0zsbigDRzTVkjqGmBXXDt9QwEsBE1l/IzrJ8tEwLBUSb8CZFPt+gI7pmAgz+Q6u+Gp2MfCFE1OcqmzOoxiHMI4Uu4wKBgQD6hs+iA8L8h2scuddIh7D2CXw3hFRakOCIKlO5Wqw9Z9J0oo1cn8Y26G2zNFkq5w8LZysmASbDi7osmbflmd1tmXB3Wmu7TahTho1xbiwi9n6F6lClfoKd+qClaaI8z+QrVy5k7rSQo4zhOnOrlIW+7aSiLOSRCtKc6tmP914D6wKBgFXPG4Jo1JN4kAhm0Oa5o55q+lnyfRq3LhrPiYKNdFhsfP1sKhnZpkcChELbZZVm+LvZDX3kqlSNO5juBwfzCj9jUIgrk9jAIO8zhFNVwJhB26NwsaBxT9pt4BoRcG4VQJKwVo+6XwWXSlIDoqOX1p/aJ/gSw4nhqP/YkwbJZke/AoGBAIoptPKl3nAEgtb5yreuVbKqsn2vlhHIWnvd1ASh8+F9k3xNdWaCmv8HGhC9qvtVKF/iitJPykAHnCoisF+Ihqx99Z9tF4LZph5CU1keKGszw7045zcN2R0k7lmrMxUUlcItN2Hkn2IxQG2qHcafh08voh7qYTd4X4S4pDmYc5n3AoGAHK2yp0N5vzqG/vB/0h1ReQ/63syF5QQK8wD+3Nw1CE2quMKljJda6FYb5th+KDyo+TAC+L9VR3d/KwnIUGw/2bf4+ZPhDbiNLe48OAILHdA3zx0akrAalcpYi22HIePT5KYqesc550+W4T002fmgffMgbDQe/4NhD6i+IFt29Y4=";

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("acleia chata", publicKey));
            System.out.println(encryptedString);
            String decryptedString = RSAUtil.decrypt(encryptedString, privateKey);
            System.out.println(decryptedString);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }

    }
}
