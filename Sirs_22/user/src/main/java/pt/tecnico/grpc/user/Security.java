package pt.tecnico.grpc.user;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.sql.Timestamp;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.net.ssl.SSLException;

import com.google.protobuf.ByteString;

import java.security.*;
import java.security.spec.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.io.DataOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class Security {
    
    /*---------------------------Private/Public Key Functions----------------------------------*/

    public static Key getPublicKey(String filename) throws Exception {
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePublic(spec);
    }


    public static Key getPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }
    
    public static void createKeys(String username) throws NoSuchAlgorithmException, Exception{

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        Key privateKey1 = pair.getPrivate();
        Key publicKey1 = pair.getPublic();

        File file = null;

        file = new File("publicKey/" + username + "-PublicKey");

        if (file.createNewFile()) {

            OutputStream os = new FileOutputStream(file);
            os.write(publicKey1.getEncoded());
            os.close();
        } 
        else{
            return;
        }

        file = new File("privateKey/" + username + "-PrivateKey");

        if (file.createNewFile()) {

            OutputStream os = new FileOutputStream(file);
            os.write(privateKey1.getEncoded());
            os.close();
        } 
        else{
            return;
        }
    }

    /*---------------------------Encryption/Decryption Functions----------------------------------*/

    public static byte[] encryptKey(byte[] input, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inputSize = input.length;
        int maxBlockSize = 117;
        int offSet = 0;
        byte[] result = {};
        byte[] iteration = {};

        while (inputSize-offSet > 0) {
            if (inputSize-offSet> maxBlockSize) {
                iteration = cipher.doFinal(input, offSet, maxBlockSize);
                offSet += maxBlockSize;
            } 
            else {
                iteration = cipher.doFinal(input, offSet, inputSize-offSet);
                offSet = inputSize;
            }
            result = Arrays.copyOf(result, result.length + iteration.length);
            System.arraycopy(iteration, 0, result, result.length-iteration.length, iteration.length);
        }

        return result;
    }


    public static byte[] decryptKey(byte[] inputArray, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inputSize = inputArray.length;
        int maxBlockSize = 128;
        int offSet = 0;
        byte[] result = {};
        byte[] iteration = {};

        while (inputSize-offSet > 0) {
            if (inputSize-offSet> maxBlockSize) {
                iteration = cipher.doFinal(inputArray, offSet, maxBlockSize);
                offSet += maxBlockSize;
            } 
            else {
                iteration = cipher.doFinal(inputArray, offSet, inputSize-offSet);
                offSet = inputSize;
            }
            result = Arrays.copyOf(result, result.length + iteration.length);
            System.arraycopy(iteration, 0, result, result.length-iteration.length, iteration.length);
        }
        return result;
    }



    public static Key createAESKey() throws Exception{

        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
 
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();
 
        return key;
    }
 
    public static byte[] createInitializationVector(){

        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(initializationVector);

        return initializationVector;
    }
 

    public static byte[] encryptAES(byte[] plainText, Key secretKey, byte[] initializationVector) throws Exception{
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
 
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
 
        return cipher.doFinal(plainText);
    }
 
    public static byte[] decryptAES(byte[] cipherText, Key secretKey, byte[] initializationVector)throws Exception{
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
 
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
 
       return cipher.doFinal(cipherText);
    }

    public static byte[] encrypt(Key key, byte[] text) {

        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            return rsa.doFinal(text); //text.getBytes()

        } 
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String decrypt(Key key, byte[] buffer) {

        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, key);
            byte[] value = rsa.doFinal(buffer);
            return new String(value);

        } 
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

        
    /*---------------------------Hash Functions----------------------------------*/

    public static String hashMessage(String secretString) throws NoSuchAlgorithmException, NoSuchProviderException{
        
        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);

        return hashtext;
    }

    public static boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
        
        String message = new String(Message);

        if((hashMessage(message).compareTo(hashMessage)) == 0)
            return true;

        return false;   
    }

    public static String convertToHex(byte[] messageDigest) {

        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);

        return hexText;
    }

    
    /*---------------------------TimeStamp Functions----------------------------------*/

    public static byte[] getTimeStampBytes(){

        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();

        return Long.toString(timeStampLong).getBytes();
    }

    public static boolean verifyTimeStamp(ByteString sentTimeStamp, Key key)  throws Exception{

        String timeStampDecrypted= decrypt(key, sentTimeStamp.toByteArray());

        long sentTimeStampLong = Long.parseLong(timeStampDecrypted);
        
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();

        if((timeStampLong - sentTimeStampLong) < 1000)
            return true;

        return false;
    }


    /*---------------------------Safe Password Function----------------------------------*/

    public static String safePassword(){

        System.out.print("Please, enter your password: ");

        StringBuilder sb = new StringBuilder("");
        char [] input = System.console().readPassword();

        boolean hasLower , hasUpper, hasDigit, hasSpecialCharacter;
        boolean safe = true; //so para testar mais rapido, colocar a false depois!!!

        while(safe == false){
            hasLower = false;
            hasUpper = false;
            hasDigit = false;
            hasSpecialCharacter = false;
            
            int len = input.length;

            if(len<10){
                System.out.println("Password must be have at least 10 characters(Lower and UpperCase, with at least 1 digit and a special character) ");
                System.out.print("Please, enter your password: ");
                input = System.console().readPassword();
            }
            else{
                for(char i : input){
                    if(i >= 65 && i <= 90){
                        hasUpper = true;
                    }
                    else if(i >= 97 && i <= 122){
                        hasLower = true;
                    }
                    else if(i >= 48 && i <= 57){
                        hasDigit = true;
                    }
                    else if((i >= 33 && i <= 47) || (i >= 58 && i <= 64) || (i >= 91 || i <= 96))
                        hasSpecialCharacter = true;
                }
                if(hasUpper && hasLower && hasDigit && hasSpecialCharacter){
                    safe = true;
                    break;
                }
                System.out.println("Password must be have at least 10 characters(Lower and UpperCase, with at least 1 digit and a special character) ");
                System.out.print("Please, enter your password: ");
                input = System.console().readPassword();
            }
        }
        sb.append(input);
        String password = sb.toString();
        return password;
    }
}
