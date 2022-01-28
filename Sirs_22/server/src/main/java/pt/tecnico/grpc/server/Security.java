package pt.tecnico.grpc.server;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.server.exceptions.*;
import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.server.Security;

import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.MainBackupServer;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.sql.Timestamp;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.lang.model.util.ElementScanner6;
import javax.net.ssl.SSLException;
import javax.sound.sampled.AudioFormat.Encoding;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.NoSuchProviderException;
import java.io.*;

import java.sql.*;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;

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

    
    /*---------------------------Hash Functions----------------------------------*/

    public String createFileChecksum(byte[] file) throws FileNotFoundException, IOException, NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(file);
      
        String checksum = convertToHex(md.digest());

        return checksum;
    }   
    
    public static String hashString(String secretString, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException{

        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        if(salt.length != 0){
            md.update(salt);
        }

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);

        return hashtext;
    }

    public static String convertToHex(byte[] messageDigest) {

        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);

        return hexText;
    }
    
    public static byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException {

      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      byte[] salt = new byte[20];
    
      random.nextBytes(salt);

      return salt;
    }

    public static String createUserHashDb(String username, String hashPassword, String hashCookie, 
        byte[] salt, byte[] encryptedPublicKey) throws Exception{

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(hashPassword.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(hashCookie.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(salt);
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPublicKey);

        byte[] message = messageBytes.toByteArray();

        return hashString(new String(message), new byte[0]);
    }

    public static String createFileHashDb(String fileID, byte[] fileContent, String fileOwner) throws Exception{

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileContent);
        messageBytes.write(":".getBytes());
        messageBytes.write(fileOwner.getBytes());
       
        byte[] message = messageBytes.toByteArray();

        return hashString(new String(message), new byte[0]);
    }

    public static String createPermissionHashDb(String fileID, String username, byte[] encryptedSymmetricKey, 
        byte[] encryptedInitializationVector) throws Exception{

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedSymmetricKey);
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedInitializationVector);

        byte[] message = messageBytes.toByteArray();

        return hashString(new String(message), new byte[0]);
    }

    public static boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{

        String message = new String(Message);

        if((hashString(message, new byte[0]).compareTo(hashMessage)) == 0)
            return true;

        return false;   
    }

    /*---------------------------TimeStamp Functions----------------------------------*/

    public static boolean verifyTimeStamp(ByteString sentTimeStamp, Key key)  throws Exception{

        String timeStampDecrypted = decrypt(key, sentTimeStamp.toByteArray());
        long sentTimeStampLong = Long.parseLong(timeStampDecrypted);
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();

        if((timeStampLong - sentTimeStampLong) < 1000)
            return true;

        return false;
    }

    public static byte[] getTimeStampBytes(){

        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();

        return Long.toString(timeStampLong).getBytes();
    }

    /*---------------------------Create Cookie Function----------------------------------*/

    public static String createCookie(String userName, String password) throws NoSuchAlgorithmException, NoSuchProviderException{
      
        String hexSalt = convertToHex(createSalt());

        String cookie = userName + password + hexSalt;

        return cookie;
    }

    /*---------------------------Encryption/Decryption Functions----------------------------------*/

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

}
