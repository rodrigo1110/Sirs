package pt.tecnico.grpc.user;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;

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



public class UserImpl {
    private String host;
	private int port;
    private String cookie = "";
    ManagedChannel channel;
    UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub;
    private static Key privateKey;
    private static Key publicKey;
    private static Key serverPublicKey;
    private static boolean hasServerPublicKey = false;
    private String username = "";
    private String target;


    public UserImpl(String Host, int Port){
        target = Host + ":" + Port;
        new File("publicKey").mkdirs();
        new File("privateKey").mkdirs();
        new File("uploads").mkdirs();
        new File("downloads").mkdirs();
	}

    public void setTarget(String Host, int Port){
        target = Host + ":" + Port;
    }

    public String getCookie(){
        return cookie;
    }

    public void hello() throws Exception{
        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);
        UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
		UserMainServer.HelloRequest request = UserMainServer.HelloRequest.newBuilder().setName("friend").build();

		UserMainServer.HelloResponse response = stub.greeting(request);
		System.out.println(response);
    }

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


    public void createKeys(String username) throws NoSuchAlgorithmException, Exception{
        //Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        Key privateKey1 = pair.getPrivate();
        Key publicKey1 = pair.getPublic();

        File file = null;
        file = new File("publicKey/" + username + "-PublicKey");
        if (file.createNewFile()) {
            System.out.println("New file created: " + file.getName());
            OutputStream os = new FileOutputStream(file);
            os.write(publicKey1.getEncoded());
            os.close();
        } 
        else{
            System.out.println("Test: existent file.");
            return;
        }

        file = new File("privateKey/" + username + "-PrivateKey");
        if (file.createNewFile()) {
            System.out.println("New file created: " + file.getName());
            OutputStream os = new FileOutputStream(file);
            os.write(privateKey1.getEncoded());
            os.close();
        } 
        else{
            System.out.println("Test: existent file.");
            return;
        }
    }


    public byte[] encryptKey(byte[] inputArray, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inputLength = inputArray.length;
        System.out.println("Encrypted bytes:" + inputLength);
        int MAX_ENCRYPT_BLOCK = 117;
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] iteration = {};

        while (inputLength-offSet> 0) {
            if (inputLength-offSet> MAX_ENCRYPT_BLOCK) {
                iteration = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                iteration = cipher.doFinal(inputArray, offSet, inputLength-offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + iteration.length);
            System.arraycopy(iteration, 0, resultBytes, resultBytes.length-iteration.length, iteration.length);
        }

        return resultBytes;
    }



    public byte[] decryptKey(byte[] inputArray, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inputLength = inputArray.length;
        System.out.println("Decrypted bytes:" + inputLength);
        int MAX_ENCRYPT_BLOCK = 128;
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] iteration = {};

        while (inputLength-offSet> 0) {
            if (inputLength-offSet> MAX_ENCRYPT_BLOCK) {
                iteration = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                iteration = cipher.doFinal(inputArray, offSet, inputLength-offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + iteration.length);
            System.arraycopy(iteration, 0, resultBytes, resultBytes.length-iteration.length, iteration.length);
        }

        return resultBytes;
    }








    public static Key createAESKey() throws Exception{
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
 
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();
 
        System.out.println("Chave simetrica gerada: " + key);
        return key;
    }
 
    public byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(initializationVector);
        System.out.println("Initialization vector: " + convertToHex(initializationVector));
        System.out.println("Initialization vector: " + initializationVector.length);
        return initializationVector;
    }
 

    public byte[] encryptAES(byte[] plainText, Key secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
 
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
 
        return cipher.doFinal(plainText);
    }
 
    
    public byte[] decryptAES(byte[] cipherText, Key secretKey, byte[] initializationVector)throws Exception{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
 
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
 
       return cipher.doFinal(cipherText);
    }




    //encrypt with public and private key --> server and user
    public byte[] encrypt(Key key, byte[] text) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            return rsa.doFinal(text); //text.getBytes()

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //derypt with public and private key --> server and user
    public String decrypt(Key key, byte[] buffer) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, key);
            byte[] value = rsa.doFinal(buffer);
            return new String(value);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }





    public String hashMessage(String secretString) throws NoSuchAlgorithmException, NoSuchProviderException{
        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);
        System.out.println("hash text:" + hashtext);
        return hashtext;
    }


    private boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
        String message = new String(Message);
        if((hashMessage(message).compareTo(hashMessage)) == 0)
            return true;
        return false;   
    }


    private String convertToHex(byte[] messageDigest) {
        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);
        return hexText;
    }


    public byte[] getTimeStampBytes(){
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();
        return Long.toString(timeStampLong).getBytes();
    }


    private boolean verifyTimeStamp(ByteString sentTimeStamp, Key key)  throws Exception{
        String timeStampDecrypted= decrypt(key, sentTimeStamp.toByteArray());
        long sentTimeStampLong = Long.parseLong(timeStampDecrypted);
        
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();
        System.out.println("TimeStamp time: " + timeStampLong);
        if((timeStampLong - sentTimeStampLong) < 32000000)
            return true;
        return false;
    }





    public String safePassword(){

        System.out.print("Please, enter your password: ");
        //String password = System.console().readLine();
        /* Para apagar depois, claro */
        //String password;
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




    public void signup() throws Exception{
		
        System.out.println("------------------------------");
        System.out.println("User Registration");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

       
        String password = safePassword();

        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("------------------------------");

        //---------------------------------------------------------------------------------------
        try{
            createKeys(userName);
            
        }catch(NoSuchAlgorithmException e) {
            System.out.println("No algorithm");
        }catch(Exception e){
            System.out.println("AQUIIIIII");
            throw new RuntimeException(e);
        }
        
        if(!hasServerPublicKey){
            serverPublicKey = getPublicKey("../server/rsaPublicKey");
            hasServerPublicKey = true;
        }



        String targetPublic = "publicKey/" + userName + "-PublicKey";
        String targetPrivate = "privateKey/" + userName + "-PrivateKey";
        publicKey = getPublicKey(targetPublic);
        privateKey = getPrivateKey(targetPrivate);
        
        ByteString encryptedPassword = ByteString.copyFrom(encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        String path = "publicKey/" + userName + "-PublicKey";
        byte[] clientPublicKeyBytes = Files.readAllBytes(Paths.get(path));
        System.out.println("CHAVE PUBLICA DO CLIENTE TOSTRING");
        System.out.println(new String(clientPublicKeyBytes));
        ByteString encryptedPublicKey = ByteString.copyFrom(encryptKey(clientPublicKeyBytes, serverPublicKey));
        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPublicKey.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());
        
        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);
        UserMainServer.signUpRequest request = UserMainServer.signUpRequest.newBuilder()
            .setUserName(userName).setPassword(encryptedPassword).setPublicKeyClient(encryptedPublicKey)
            .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        stub.signUp(request);
        
        System.out.println("Successful Registration! Welcome " + userName + ".");
    }    
    


    public void login() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        StringBuilder sb = new StringBuilder("");
        System.out.print("Please, enter your password: ");
		char [] input = System.console().readPassword();
        sb.append(input);
        String password = sb.toString();
        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("-------- ----------------------");

        

        if(!hasServerPublicKey){
            serverPublicKey = getPublicKey("../server/rsaPublicKey");
            hasServerPublicKey = true;
        }
        try{
            String targetPublic = "publicKey/" + userName + "-PublicKey";
            String targetPrivate = "privateKey/" + userName + "-PrivateKey";
            publicKey = getPublicKey(targetPublic);
            privateKey = getPrivateKey(targetPrivate);
        }catch(NoSuchFileException e){
            System.out.println("User not existent locally. Must sign up locally first.");
            return;
        }

        ByteString encryptedPassword = ByteString.copyFrom(encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));

        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);
        UserMainServer.loginRequest request = UserMainServer.loginRequest.newBuilder().
        setUserName(userName).setPassword(encryptedPassword)
        .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        UserMainServer.loginResponse response = stub.login(request);

        byte[] cookie = response.getCookie().toByteArray();
        String cookieDecrypted = decrypt(privateKey, cookie);
        byte[] hashCookie = response.getHashCookie().toByteArray();
        String hashCookieDecrypted = decrypt(serverPublicKey, hashCookie);

        if(!verifyMessageHash(cookieDecrypted.getBytes(), hashCookieDecrypted)){
            System.out.println("Response message corrupted.");
            return;
        }

        System.out.println(response);
        this.cookie = cookieDecrypted;

        System.out.println("COOKIE: " + cookieDecrypted);

        username = userName;

        System.out.println("Successful Login! Welcome back " + userName + ".");
    }



    public void logout() throws Exception{
 		      
        String hashCookie = hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));


        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));
        
        
        UserMainServer.logoutRequest request = UserMainServer.logoutRequest.
        newBuilder().setCookie(encryptedhashCookie).setTimeStamp(encryptedTimeStamp).
        setHashMessage(encryptedHashMessage).build();

        stub.logout(request);
            
        cookie = "";
        System.out.println("Successful logout.");
    }




    public void share() throws Exception{
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to share: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to share this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username" + counter + ": ");
            counter++;
            userName = System.console().readLine();
            listOfUsers.add(userName);
        }
        //delete de 'x'
        listOfUsers.remove(listOfUsers.size()-1);

        //para testar
        System.out.println("list of users to string: " + listOfUsers.toString());
        System.out.println(listOfUsers.toString());
        System.out.println(listOfUsers.size());

        if(listOfUsers.size() == 0){
            System.out.println("You must insert at least one user to share this file with.");
            return;
        }

        //-------------File Obtained from Uploads Directory
        

        String hashCookie = hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.shareRequest request = UserMainServer.shareRequest.newBuilder().
            setFileId(fileName).addAllUserName(listOfUsers).setCookie(encryptedhashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        UserMainServer.shareResponse response = stub.share(request);


        //-----------------Verify response and obtain its fields--------------

        //chave simetrica (que encriptou o ficheiro) encriptada com a chave publica do (cada um) cliente que tem acesso ao ficheiro
        //Obter campos shareResponse
        byte[] encryptedSymmetricKeyByteArray = response.getSymmetricKey().toByteArray();
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        List<ByteString> encryptedPublicKeyList = response.getPublicKeysList(); //ENVIAR ISTO ASSIM COMO STRING DO SERVDIOR
        

        byte[] SymmetricKeyByteArray = decryptKey(encryptedSymmetricKeyByteArray, privateKey);
        
        List<byte[]> listOfPublicKeys = new ArrayList<byte[]>();
        
        System.out.println("Response public key list size: " + response.getPublicKeysList().size());
        for(int i = 0; i < response.getPublicKeysList().size(); i++){
            System.out.println("Response public key list element: " + response.getPublicKeys(i).toByteArray());
            listOfPublicKeys.add(decryptKey(response.getPublicKeys(i).toByteArray(), privateKey)); //do lado ddo servidor temos de encriptar cada elemento da lista individualmente
        }


        if(!verifyTimeStamp(response.getTimeStamp(),serverPublicKey)){
            System.out.println("Response took to long");
            return;
        }


        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());

        for(int i = 0; i < encryptedPublicKeyList.size(); i++ ){
            responseBytes.write(encryptedPublicKeyList.get(i).toByteArray()); //-------This one is different from the one sent by server by a few bits
            responseBytes.write(":".getBytes());
        }
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!verifyMessageHash(responseBytes.toByteArray(), hashResponseString)){
            System.out.println("Response integrity compromised");
        } 


        System.out.println("SymmetricKey from " + fileName + " was successfully obtained.");
        shareKey(listOfPublicKeys, listOfUsers, SymmetricKeyByteArray, fileName, encryptedhashCookie);
        System.out.println("The file " + fileName + " was successfully shared.");
    }

    


    public void shareKey(List<byte[]> listOfPublicKeys, List<String> listOfUsers,
        byte[] symmetricKey, String fileName, ByteString encryptedHashCookie) throws Exception{
        

        List<ByteString> listOfEncryptedSymmetricKeysByteString = new ArrayList<>();

        for(int i = 0; i < listOfPublicKeys.size(); i++){
            X509EncodedKeySpec spec = new X509EncodedKeySpec(listOfPublicKeys.get(i));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            Key userPublicKey = kf.generatePublic(spec);
            //do lado do servidor temos de encriptar cada elemento da lista individualmente
            listOfEncryptedSymmetricKeysByteString.add(ByteString.copyFrom(encryptKey(symmetricKey, userPublicKey)));
        }

        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        
        for(int i = 0; i < listOfEncryptedSymmetricKeysByteString.size(); i++ ){
            messageBytes.write(listOfEncryptedSymmetricKeysByteString.get(i).toByteArray()); 
            messageBytes.write(":".getBytes());
        }
        
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


    
        UserMainServer.shareKeyRequest request = UserMainServer.shareKeyRequest.newBuilder().
            setFileId(fileName).addAllSymmetricKey(listOfEncryptedSymmetricKeysByteString).addAllUserNames(listOfUsers).setCookie(encryptedHashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        
        stub.shareKey(request);
    }


    public void unshare() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to unshare: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to unshare this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username" + counter + ": ");
            counter++;
            userName = System.console().readLine();
            listOfUsers.add(userName);
        }
        //delete de 'x'
         listOfUsers.remove(listOfUsers.size()-1);

         //para testar
        System.out.println("list of users to string: " + listOfUsers.toString());
        System.out.println(listOfUsers.toString());
        System.out.println(listOfUsers.size());




        String hashCookie = hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));

        
        UserMainServer.unshareRequest request = UserMainServer.unshareRequest.newBuilder().setFileId(fileName)
            .addAllUserName(listOfUsers).setCookie(encryptedhashCookie)
            .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
    
        stub.unshare(request);

        System.out.println("The file " + fileName + " was successfully unshared.");
    }
    



    public void downloadLocally(String fileName, byte[] decryptedFileContentByteArray) throws Exception{
        File file = null;
        file = new File("downloads/" + fileName);

        if (file.createNewFile()) {
            System.out.println("New file created: " + file.getName());
            OutputStream os = new FileOutputStream(file);
            os.write(decryptedFileContentByteArray);
            os.close();
            System.out.println("Successful Download! You can find your downloaded file in your downloads directory.");
        } 
        else {
            System.out.println("A file with the same name already exists in your downloads directory. Are you sure you want to replace it? (Y/n)");
            System.out.print("> ");
            String replace = System.console().readLine();
            
            if(replace.compareTo("Y") == 0){
                if (file.delete()) {
                    System.out.println("File replaced successfully");
                    OutputStream os = new FileOutputStream(file);
                    os.write(decryptedFileContentByteArray);
                    os.close();
                    System.out.println("Successful Download! You can find your downloaded file in your downloads directory.");
                }
                else 
                    System.out.println("Failed to delete the file");
            }
            else
                System.out.println("File was not replaced.");
        }
    }

    

    public void download() throws Exception{
		
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to download: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        
        String hashCookie = hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.downloadRequest request = UserMainServer.downloadRequest.newBuilder().
            setFileId(fileName).setCookie(encryptedhashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        UserMainServer.downloadResponse response = stub.download(request);


        byte[] encryptedFileContentByteArray = response.getFileContent().toByteArray();
        byte[] encryptedSymmetricKeyByteArray = response.getKey().toByteArray();
        byte[] initializationVectorByteArray = response.getInitializationVector().toByteArray();
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();

        
        if(!verifyTimeStamp(response.getTimeStamp(),serverPublicKey)){
            System.out.println("Response took to long");
            return;
        }

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(encryptedFileContentByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(initializationVectorByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        System.out.println("################");

        String hashResponseString = decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!verifyMessageHash(responseBytes.toByteArray(), hashResponseString)){
            System.out.println("Response integrity compromised");
            return;
        }

        System.out.println("1111111111111111111111");

        byte[] decryptedSymmetricKeyByteArray =  decryptKey(encryptedSymmetricKeyByteArray, privateKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedSymmetricKeyByteArray, 0, decryptedSymmetricKeyByteArray.length, "AES");

        System.out.println("2222222222222");

        System.out.println("DecryptedInitializationVector: " + convertToHex(initializationVectorByteArray));
        System.out.println("DecryptedInitializationVector Size: " + initializationVectorByteArray.length);
        byte[] decryptedFileContentByteArray = decryptAES(encryptedFileContentByteArray, decryptedSymmetricKey, initializationVectorByteArray);
        System.out.println("33333333333333333");


        downloadLocally(fileName,decryptedFileContentByteArray);
            
    }


    public UserMainServer.isUpdateResponse isUpdate(String fileName, ByteString encryptedHashCookie) throws Exception{
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.isUpdateRequest request = UserMainServer.isUpdateRequest.newBuilder().
                setFileId(fileName).setTimeStamp(encryptedTimeStamp).setCookie(encryptedHashCookie).
                setHashMessage(encryptedHashMessage).build();
        UserMainServer.isUpdateResponse response = stub.isUpdate(request);




        byte isUpdate = (byte)(response.getIsUpdate()?1:0);
        byte[] encryptedSymmetricKeyByteArray = response.getSymmetricKey().toByteArray();
        byte[] initializationVectorByteArray = response.getInitializationVector().toByteArray();
        System.out.println("IsUpdate Initialization Vector: " + new String(initializationVectorByteArray));
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        
        if(!verifyTimeStamp(response.getTimeStamp(),serverPublicKey)){
            System.out.println("Response took to long");
            return null;
        }

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(isUpdate);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(initializationVectorByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!verifyMessageHash(responseBytes.toByteArray(), hashResponseString)){
            System.out.println("Response integrity compromised");
            return null;
        }
        return response;
    }



    
    public void upload() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to upload: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        byte[] byteArray = new byte[0];
        try{
            Path path = Paths.get("uploads/" + fileName);
            byteArray = Files.readAllBytes(path);
        }catch (Exception e){
            if(e.getClass().toString().compareTo("class java.nio.file.NoSuchFileException") == 0)
                System.out.println("That file does not exist in your uploads directory.");
            return;
        }

        String hashCookie = hashMessage(cookie);
        ByteString encryptedHashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));


        UserMainServer.isUpdateResponse response = isUpdate(fileName,encryptedHashCookie);

    
        Key SymmetricKey;
        byte[] symmetricKeyArray;
        byte[] initializationVector;

        if(response == null)
            return;
        if(response.getIsUpdate()){
            symmetricKeyArray = decryptKey(response.getSymmetricKey().toByteArray(), privateKey);
            SymmetricKey = new SecretKeySpec(symmetricKeyArray, 0, symmetricKeyArray.length, "AES");
            initializationVector = response.getInitializationVector().toByteArray();
            System.out.println("Existent file's symmetric key obtained");
        }
        else{
            SymmetricKey = createAESKey();
            symmetricKeyArray = SymmetricKey.getEncoded(); //se der erro ---> outra forma
            initializationVector = createInitializationVector();
            System.out.println("New file's symmetric key generated");
        }
        byte[] encryptedFileContentBytes = encryptAES(byteArray, SymmetricKey, initializationVector);
        ByteString encryptedFileContentByteString = ByteString.copyFrom(encryptedFileContentBytes);
        System.out.println("Encrypted Message: " + new String(encryptedFileContentBytes));
        
        
        
        ByteString encryptedSymmetricKey = ByteString.copyFrom(encryptKey(symmetricKeyArray, publicKey));
        ByteString initializationVectorByteString = ByteString.copyFrom(initializationVector);
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));
        //byte[] decryptedText = decryptAES(cipherText, SymmetricKey, initializationVector);
        //System.out.println("Original Message: " + new String(decryptedText));
        
        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedFileContentBytes);
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedSymmetricKey.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(initializationVectorByteString.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


        //a funcao de hash de ficheiros recebe argumento do tipo ByteString
        //encripta a hash com a chave privada do cliente
        //encripta o bytestring com chave simetrica (gerada por aes - 256, block cbc)
        //encriptar chave simetrica com chave publica do servidor 

        UserMainServer.uploadRequest request = UserMainServer.uploadRequest.newBuilder().
        setFileId(fileName).setFileContent(encryptedFileContentByteString).
        setSymmetricKey(encryptedSymmetricKey).setInitializationVector(initializationVectorByteString).
        setTimeStamp(encryptedTimeStamp).setCookie(encryptedHashCookie).
        setHashMessage(encryptedHashMessage).build();

        stub.upload(request);

        System.out.println("Successful Upload!");
    }


    public void deleteUser() throws Exception{
            
        System.out.println("------------------------------");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        StringBuilder sb = new StringBuilder("");
        System.out.print("Please, enter your password: ");
		char [] input = System.console().readPassword();
        sb.append(input);
        String password = sb.toString();
        // Para apagar depois, claro xD
        System.out.println("You entered the password " + password);
        System.out.println("-------- ----------------------");

        
        
        ByteString encryptedPassword = ByteString.copyFrom(encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));
        
        
        UserMainServer.deleteUserRequest request = UserMainServer.deleteUserRequest.newBuilder().setUserName(userName)
            .setPassword(encryptedPassword).setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        stub.deleteUser(request);

        File file = new File("publicKey/" + username + "-PublicKey");

        if (file.delete()) {
            System.out.println("Public Key file deleted successfully.");
        }
        else 
            System.out.println("Failed to delete the file");


        file = new File("privateKey/" + username + "-PrivateKey");

        if (file.delete()) {
            System.out.println("Private Key file deleted successfully.");
        }
        else 
            System.out.println("Failed to delete the file");
            
        System.out.println("User deleted successfully!");
        cookie = "";
    }



    public void deleteFile() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to delete: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        
        String hashCookie = hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(encrypt(serverPublicKey, hashCookie.getBytes()));


        ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));

        
        UserMainServer.deleteFileRequest request = UserMainServer.deleteFileRequest.newBuilder().setFileId(fileName)
            .setCookie(encryptedhashCookie).setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        stub.deleteFile(request);
    
        System.out.println("The file " + fileName + " was successfully deleted.");
    }
}
