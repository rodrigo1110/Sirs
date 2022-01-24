package pt.tecnico.grpc.server;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.server.exceptions.*;
import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.MainBackupServer;

import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;

import java.io.File;
import java.io.InvalidClassException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.sql.Timestamp;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.sound.sampled.AudioFormat.Encoding;

import java.nio.file.Paths;
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


public class mainServer {
    
    //--------------------------user-mainServer implementation--------------------------
    ManagedChannel channel;
    MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub stub;
    boolean clientActive = false;
    private databaseAccess database = new databaseAccess("rda");
    Connection connection = database.connect();
    private String userName;
    private String password;
    private Key privateKey;
    private Key publicKey;
    private boolean hasKeys = false;


    public mainServer(Boolean flag, ManagedChannel Channel, MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub Stub){
        if(flag){
            channel = Channel;
            stub = Stub;
            clientActive = true;
        }
        
    }
    
    public String greet(String name){
        if(clientActive){ //Just for testing, delete later and write function to make requests to backup
            MainBackupServer.HelloRequest request = MainBackupServer.HelloRequest.newBuilder().setName("buddy").build();
		    MainBackupServer.HelloResponse response = stub.greeting(request);
        }
        return "Hello my dear " + name + "!";
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


    
    public String createFileChecksum(byte[] file) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(file);
      
        String checksum = convertToHex(md.digest());
        System.out.println("checksum ficheiro: " + checksum);
        return checksum;
    }   
    
    
    public String hashString(String secretString, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException{

        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        if(salt.length != 0){
            md.update(salt);
            System.out.println("Sal: " + salt);
        }

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);
        System.out.println("hash text:" + hashtext);
        return hashtext;
    }

    private String convertToHex(byte[] messageDigest) {
        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);
        return hexText;
    }
    
    private byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      byte[] salt = new byte[20];
    
      random.nextBytes(salt);
      return salt;
    }


    private boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
        String message = new String(Message);
        if((hashString(message, new byte[0]).compareTo(hashMessage)) == 0)
            return true;
        return false;   
    }

    private boolean verifyTimeStamp(ByteString sentTimeStamp, Key key)  throws Exception{
        String timeStampDecrypted= decrypt(key, sentTimeStamp.toByteArray());
        long sentTimeStampLong = Long.parseLong(timeStampDecrypted);
        
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();
        System.out.println("TimeStamp time: " + timeStampLong);
        if((timeStampLong - sentTimeStampLong) < 3200)
            return true;
        return false;
    }



    //encrypt with public and private key --> server and user
    private byte[] encrypt(Key key, byte[] text) {
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
    private String decrypt(Key key, byte[] buffer) {
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


    public Key decryptKey(byte[] inputArray, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inputLength = inputArray.length;
        System.out.println("Encrypted bytes:" + inputLength);
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

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(resultBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key keyResult = keyFactory.generatePublic(keySpec);
        
        return keyResult;
    }


    public void sendUserToBackUp(String username, String hashPassword, byte[] salt){

        final String target = "localhost" + ":" + "8092";

        ByteString saltByteString = ByteString.copyFrom(salt);

        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.writeUserRequest request = MainBackupServer.writeUserRequest.newBuilder().setUsername(username).setHashPassword(hashPassword).setSalt(saltByteString).build();
            MainBackupServer.writeUserResponse response = stub.writeUser(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }


    public void sendPermissionToBackUp(String fileName, String userName){

        final String target = "localhost" + ":" + "8092";


        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.writePermissionRequest request = MainBackupServer.writePermissionRequest.newBuilder().setFileName(fileName).setUserName(userName).build();
            MainBackupServer.writePermissionResponse response = stub.writePermission(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }

    public void removePermissionFromBackUp(String fileName, String userName){

        final String target = "localhost" + ":" + "8092";


        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.removePermissionRequest request = MainBackupServer.removePermissionRequest.newBuilder().setFileName(fileName).setUserName(userName).build();
            MainBackupServer.removePermissionResponse response = stub.removePermission(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }

    public void sendFileToBackUp(String filename, ByteString filecontent,  String fileowner){

        final String target = "localhost" + ":" + "8092";


        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.writeFileRequest request = MainBackupServer.writeFileRequest.newBuilder().setFileName(filename).setFileContent(filecontent).setFileOwner(fileowner).build();
            MainBackupServer.writeFileResponse response = stub.writeFile(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }
    
    public void updateCookieBackUp(String userName, String cookie){
 
        final String target = "localhost" + ":" + "8092";


        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.updateCookieRequest request = MainBackupServer.updateCookieRequest.newBuilder().setUserName(userName).setCookie(cookie).build();
            MainBackupServer.updateCookieResponse response = stub.updateCookie(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }
   
    public void deleteFileBackUp(String fileName){
 
        final String target = "localhost" + ":" + "8092";

        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.deleteFileRequest request = MainBackupServer.deleteFileRequest.newBuilder().setFileName(fileName).build();
            MainBackupServer.deleteFileResponse response = stub.deleteFile(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }

    public void deleteUserBackUp(String userName){
 
        final String target = "localhost" + ":" + "8092";

        File tls_cert = new File("tlscert/backupServer.crt");
        try{

            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = MainBackupServerServiceGrpc.newBlockingStub(channel);

            MainBackupServer.deleteUserRequest request = MainBackupServer.deleteUserRequest.newBuilder().setUserName(userName).build();
            MainBackupServer.deleteUserResponse response = stub.deleteUser(request);
        }
        catch(SSLException e){
            System.out.println(e);
        }
    }
    //encrypt with symmetric key --> user

    //decrypt with public key --> server and user
    //decrypt with private key --> server and user
    //decrypt with symmetric key --> user

    
    public void signUp(String username, ByteString password_bytes, ByteString publickeyClient, ByteString timeStamp, ByteString hashMessage) throws Exception{
    
        if(!hasKeys){
            privateKey = getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = getPublicKey("rsaPublicKey");
            hasKeys = true;
        }


        Key clientPubKey = decryptKey(publickeyClient.toByteArray(), privateKey);

        if(!verifyTimeStamp(timeStamp, clientPubKey))
            throw new TimestampException();


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(password_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(publickeyClient.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        String hashMessageString = decrypt(clientPubKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        byte[] encryptedHashMessage = encrypt(publicKey, hashMessageString.getBytes());

        
        String password = decrypt(privateKey, password_bytes.toByteArray());
        System.out.println("Password: " + password);


        if(checkInput(username, password)){
            String query = "SELECT username FROM users WHERE username=?";

            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, username);
            
                ResultSet rs = st.executeQuery();        

                if(rs.next()) {                       
                    String name = rs.getString(1);        
                    System.out.println("Username = " + name);
                    throw new ExistentUsernameException();
                }
                else{
                    query = "INSERT INTO users ("
                    + " username,"
                    + " password, "
                    + " salt, "
                    + " publickey, "
                    + " hash ) VALUES (" //wrong hash. save hash of line
                    + "?, ?, ?, ?, ?)";
                    byte[] salt = createSalt();

                    try {
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                        st.setString(2, hashString(password, salt));
                        st.setBytes(3, salt);
                        st.setBytes(4, publickeyClient.toByteArray());
                        st.setBytes(5, encryptedHashMessage);


                        st.executeUpdate();
                        st.close();
                    } 
                    catch(SQLException e){
                          System.out.println("!!!!!!" + e);
                    }

                    sendUserToBackUp(username, hashString(password, salt), salt);

                }
            } catch(SQLException e){
                System.out.println(e);
            }         
        }
    }

    public String createCookie(String userName, String password) throws NoSuchAlgorithmException, NoSuchProviderException{
      
        String hexSalt = convertToHex(createSalt());
        //String salt_string = new String(createSalt(), StandardCharsets.UTF_8);

        String cookie = userName + password + hexSalt;
        System.out.println("bolacha: " + cookie);
        return cookie;
    }

    public UserMainServer.loginResponse login(String username, ByteString password_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        byte[] salt = new byte[0];
        String dbPassword = "";

        System.out.println("User " + username + " has attempted to login with password " + password + ".");

        if(!hasKeys){
            privateKey = getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = getPublicKey("rsaPublicKey");
            hasKeys = true;
        }

        //Key encryptedUserPublicKey = null;
        Key userPublicKey = null;

        String query = "SELECT publickey FROM users WHERE username=?";
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, username);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                byte[] userPublicKeyByteArray = rs.getBytes(1);   
                System.out.println("User public key: " + userPublicKeyByteArray);
                /*X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                userPublicKey = keyFactory.generatePublic(keySpec);*/
               userPublicKey = decryptKey(userPublicKeyByteArray, privateKey);
            }
        }
        catch(Exception e){
            System.out.println(e);
        }    

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,userPublicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(password_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(userPublicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }

        String password = decrypt(privateKey, password_bytes.toByteArray());

        if(checkInput(username, password)){

            //check if user is registered
            query = "SELECT username FROM users WHERE username=?";
            try{
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, username);
            
                ResultSet rs = st.executeQuery();        

                if(rs.next()) {                       
                    String user = rs.getString(1);        
                    
                    System.out.println("O user existe " + user);
                    

                    //check if password is correct
                    query = "SELECT password FROM users WHERE username=?";

                    try {
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                    
                        rs = st.executeQuery();        
        
                        while (rs.next()) {                       
                            dbPassword = rs.getString(1);        
                            
                            System.out.println("Password from database = " + dbPassword);
                            System.out.println("Password from user = " + password);
                            System.out.println("passwords iguais: " + dbPassword.compareTo(password));
        
                        }

                        //
                        query = "SELECT salt FROM users WHERE username=?";
                        
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                    
                        rs = st.executeQuery();
                        
                        while (rs.next()) {                       
                            salt = rs.getBytes(1);        
                            System.out.println("Salt = " + salt);  
                        }    
                        String hashPassword = hashString(password,salt);                    


                        //Integer equals = dbPassword.compareTo(password); // 0 se sao iguais
                        if((dbPassword.compareTo(hashPassword)) != 0){
                            throw new WrongPasswordException();
                        }
                        else{
                            System.out.println("User " + username + " logged in with password " + password + ".");
                            this.userName = username;
                            this.password = password;


                                                        
                            //creates cookie and adds it to database
                            String cookie = createCookie(username, password);
                            byte[] encrypted = encrypt(privateKey, cookie.getBytes());
                            System.out.println("Bolacha encriptada: " + convertToHex(encrypted));
                            System.out.println("Bolacha desencriptada: " + decrypt(publicKey, encrypted));

                            //criar/atualizar cookie na base de dados
                            query = "UPDATE users SET cookie=? WHERE username=?";
                
                            try {
                                st = connection.prepareStatement(query);
                                st.setString(1, hashString(cookie, new byte[0]));
                                st.setString(2, username);
                            
                                st.executeUpdate();
                                st.close();
                            } catch(SQLException e){
                                System.out.println("Couldn't update cookie" + e);
                            }

                            updateCookieBackUp(username, hashString(cookie, new byte[0]));

                            byte[] encryptedCookie = encrypt(userPublicKey, cookie.getBytes()); //este public key vai ter de ser a public key do user -> server vai busca-la a bd
                            String hashCookie = hashString(cookie, new byte[0]);
                            byte[] encryptedHash = encrypt(privateKey, hashCookie.getBytes());

                            UserMainServer.loginResponse response= UserMainServer.loginResponse.newBuilder()
			                .setCookie(ByteString.copyFrom(encryptedCookie)).setHashCookie(ByteString.copyFrom(encryptedHash)).build();
                            return response;
                        }
        
                        } catch(SQLException e){
                            System.out.println(e);
                        }
                }
                else{
                    throw new UserDoesNotExistException();
                }
            } catch(SQLException e){
                System.out.println(e.toString());
            }
            return UserMainServer.loginResponse.newBuilder().build();
        }
        else
            throw new RansomwareAttackException();
    }

    public boolean checkIfUserExists(String userName){
        String query = "SELECT username FROM users WHERE username=?";
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String user = rs.getString(1);        
                
                System.out.println("O user existe " + user);

                return true;
            }
            else{
                return false;
            }
        } catch(SQLException e){
            System.out.println(e.toString());
        }
        return false;
    }

    public boolean checkIfFileExists(String fileName){
        String query = "SELECT filename FROM files WHERE filename=?";
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String file = rs.getString(1);        
                
                System.out.println("O file existe " + file);

                return true;
            }
            else{
                return false;
            }
        } catch(SQLException e){
            System.out.println(e.toString());
        }
        return false;
    }

    public boolean checkFileOwner(String fileName, String userName){
        String query = "SELECT fileowner FROM files WHERE filename=?";
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String dbUserName = rs.getString(1);        
                
                System.out.println("O dono do fichero na bd e " + dbUserName);
                System.out.println("O dono do fichero na cookie e " + userName);


                if(userName.compareTo(dbUserName) == 0){
                    System.out.println("Correct owner.");
                    return true;
                }
            }
            else{
                return false;
            }
        } catch(SQLException e){
            System.out.println(e.toString());
        }
        return false;
    }

    public boolean checkIfUserAlreadyHasPermission(String fileName, String userName){
        String query = "SELECT * FROM permissions WHERE filename=? AND username=?";
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
            st.setString(2, userName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                             
                System.out.println("User " + userName + " already has permission to access file " + fileName +".");
                return true;
            }
            else{
                System.out.println("User " + userName + " doesn't have acess to " + fileName +" yet.");
                return false;
            }
        } catch(SQLException e){
            System.out.println(e.toString());
        }
        return false;
    }

    public boolean checkInput(String userName, String password){
        return userName.length() <= 45 && userName.length() > 0 && password.length() <= 45 && password.length() > 0;
    }


    public void logout(ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }

        //desencriptar a cookie
        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());
        
        String dbUserName = correspondentUser(cookie);

        String query = "UPDATE users SET cookie=? WHERE username=?";
                
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, "");
            st.setString(2, dbUserName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
              System.out.println("Couldn't update cookie" + e);
        }
        updateCookieBackUp(dbUserName, "");
    }


    public void upload(String fileID, ByteString cookie_bytes, ByteString file, ByteString symmetricKey, 
                        ByteString inicializationVector, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(file.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(symmetricKey.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(inicializationVector.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        
        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());

        try {
            //for testing, creates file with same content to check byte conversion to string
            File myObj = new File(fileID);
            if (myObj.createNewFile()) {
              System.out.println("File created: " + myObj.getName());

              OutputStream os = new FileOutputStream(myObj);
  
              os.write(file.toByteArray());
              System.out.println("Successfully byte inserted");
      
              // Close the file
              os.close();
            } 
            
            else {
              System.out.println("File already exists.");
            }
          
        } catch(Exception e){
            System.out.println(e.toString());
        }

       createFileChecksum(file.toByteArray()); 

//desencriptar a chave simetrica com a chave privada do servidor
//desencriptar o ficheiro com a chave simetrica obtida antes
//desencriptar o hash com a chave publica do cliente
//fazer hash do ficheiro e comparar --> desencriptar ficheiro

//ou
//cliente envia: (hash do ficheiro encriptado com a chave simetrica) encriptado com a chave privada do cliente, ficheiro encriptado com a  chave simetrica, chave simetrica encriptada com a chave publica do cliente + possivelmente o hash da chave simetrica encriptada com a chave publica do cliente e tudo isto encriptado com a chave privada do cliente
//desencriptar o hash(este e o hash do ficheiro encriptado com a chave simetrica) com a chave publica do cliente
//calcular a hash do ficheiro encriptado com a chave simetrica
//guardar da bd tabela ficheiros e ficheiro encriptado com chave simetrica
//guardar na tabla das permissoes a chave simetrica encriptada com a chave publica do cliente
//ter em atencao: upload ficheiro novo vs. upload de um ficheiro que ja existe

        //vamos ter de ir consultar a tabela dos utilizadores para ver a qual corresponde a cookie recebida e a partir dai e que sabemos quem e o file owner
        String dbUserName = correspondentUser(cookie);

        String query = "INSERT INTO files ("
        + " filename,"
        + " filecontent,"
        + " fileowner ) VALUES ("
        + "?, ?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileID);
            st.setBytes(2, file.toByteArray());
            System.out.println("dbUserName no upload no fileowner " + dbUserName);

            st.setString(3, dbUserName);

        
            st.executeUpdate();
            st.close();
        } catch(SQLException e){
              System.out.println(e);
        }

        sendFileToBackUp(fileID, file, dbUserName);
        // add owner to permissions table

        query = "INSERT INTO permissions ("
        + " filename,"
        + " username ) VALUES ("
        + "?, ?)";

        try {
            System.out.println("dbUserName no upload nas permisssoes " + dbUserName);
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileID);
            st.setString(2, dbUserName);
        
            st.executeUpdate();
            st.close();
        } catch(SQLException e){
                System.out.println("wwwww" + e);

        }

        sendPermissionToBackUp(fileID, dbUserName);
    }

    public String correspondentUser(String cookie) throws Exception{

        String dbUserName = "";

        if (cookie.length() == 0)
            throw new InvalidCookieException();

        String query = "SELECT username FROM users WHERE cookie=?";


        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, hashString(cookie,new byte[0]));
        
            ResultSet rs = st.executeQuery();        

            if (rs.next()) {      
                dbUserName = rs.getString("username");
                System.out.println("Username: " + dbUserName);
                return dbUserName;
            }
            else
                throw new InvalidCookieException();
        } catch(SQLException e){
                System.out.println(e);
        }
        System.out.println("Username fora do try e if: " + dbUserName);

        return dbUserName;
    }

    public UserMainServer.downloadResponse download(String fileID, ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage ) throws Exception{

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        //encontrar username correspondente a cookie recebida

        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());

        String dbUserName = correspondentUser(cookie);
        /********************************** */
        System.out.println("Username no download: " + dbUserName);


        if(checkIfUserAlreadyHasPermission(fileID, dbUserName)){
             String query = "SELECT filecontent FROM files WHERE filename=?";

            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, fileID);
            
                ResultSet rs = st.executeQuery();        
    
                if (rs.next()) {      
    
                    ByteString bytestring = ByteString.copyFrom(rs.getBytes(1));
                    System.out.println("File content = " + bytestring.toStringUtf8());
    
                    UserMainServer.downloadResponse response = UserMainServer.downloadResponse.newBuilder()
				        .setFileContent(bytestring).build();
                    
                    return response;
                }
                else{
                    throw new FileUnknownException(fileID);
                }
    
            } catch(SQLException e){
                    System.out.println(e);
            }
        }
        else{
            throw new NotSharedWithUserException();
        }
        return UserMainServer.downloadResponse.newBuilder().build();
    }


    public UserMainServer.shareResponse share(String fileID, ByteString cookie_bytes, List<String> user, ByteString timeStamp, ByteString hashMessage) throws Exception{ //se um dos nomes inseridos pelo user estiver errado, mais nenhum e adicionado, por causa da excecao.
    
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(user.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        
        //check if the file exists - done
        //check if "I" am the owner of the file - done, need to update after cookie done
        //check if user already had permission - done


        //cliente pede ao servidor chave simetrica (que esta na bd encriptada com a publica do cliente) e a chave publica da pessoa com quem quer partilhar
        //cliente encripta a chave simetrica com a chave publica (enviada pelo servidor) da pessoa com quem quer partilhar o ficheiro
        //cliente envia esta chave simetrica encriptada com a publica da outra pessoa para o servidor colocar isto na coluna (chave) da tabela permissoes na linha da pessoa BOB
        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());
        
        String dbUserName = correspondentUser(cookie);


        for (String userName : user) {
            if(checkIfFileExists(fileID)){
                if(checkIfUserExists(userName)){
                    if(checkFileOwner(fileID, dbUserName)){
                        if(!checkIfUserAlreadyHasPermission(fileID, userName)){


                            String query = "INSERT INTO permissions ("
                            + " filename,"
                            + " username ) VALUES ("
                            + "?, ?)";
                    
                            try {
                                PreparedStatement st = connection.prepareStatement(query);
                                st.setString(1, fileID);
                                st.setString(2, userName);
                            
                                st.executeUpdate();
                                st.close();
                            } catch(SQLException e){
                                    System.out.println("?????" + e);
                    
                            }

                            sendPermissionToBackUp(fileID, userName);

                        }
                        else{
                            throw new UserAlreadyHasAccessException(userName);
                        }
                    }
                    else{
                        throw new WrongOwnerException();
                    }
                }
                else{
                    throw new UserUnknownException(userName);
                }    
            }
            else{
                throw new FileUnknownException(fileID);
            }

        }
        return UserMainServer.shareResponse.newBuilder().build();

    }


    public UserMainServer.shareKeyResponse shareKey(ByteString cookie_bytes,List<ByteString> symmetricKeyList,
        List<ByteString> initializationVectorList, List<String> userNameList, String fileName, 
        ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(symmetricKeyList.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(initializationVectorList.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(userNameList.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        
        return UserMainServer.shareKeyResponse.newBuilder().build();
    }

    


    public void unshare(String fileID, ByteString cookie_bytes, List<String> user, ByteString timeStamp, ByteString hashMessage) throws Exception{ //se um dos nomes inseridos pelo user estiver errado, mais nenhum e adicionado, por causa da excecao.
        
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(user.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        //check if the file exists - done
        //check if "I" am the owner of the file - done, need to update after cookie done
        //check if user already had permission - done

        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());


        String dbUserName = correspondentUser(cookie);


        for (String userName : user) {
            if(checkIfFileExists(fileID)){
                if(checkIfUserExists(userName)){
                    if(checkFileOwner(fileID, dbUserName)){
                        if(checkIfUserAlreadyHasPermission(fileID, userName)){

                            String query = "DELETE FROM permissions WHERE filename=? AND username=?";
                    
                            try {
                                PreparedStatement st = connection.prepareStatement(query);
                                st.setString(1, fileID);
                                st.setString(2, userName);
                            
                                st.executeUpdate();
                                st.close();
                            } 
                            catch(SQLException e){
                                    System.out.println("?????" + e);
                            }

                            removePermissionFromBackUp(fileID, userName);
                        }
                        else{
                            throw new UserAlreadyHasAccessException(userName);
                        }
                    }
                    else{
                        throw new WrongOwnerException();
                    }
                }
                else{
                    throw new UserUnknownException(userName);
                }    
            }
            else{
                throw new FileUnknownException(fileID);
            }

        }

    }


    public void deleteUser(String userName, ByteString password_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(password_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        
        String password = decrypt(privateKey, password_bytes.toByteArray());
        byte[] salt = new byte[0];
        String query = "SELECT password FROM users WHERE username=?";
        String dbPassword = "";
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                dbPassword = rs.getString(1);        
                
                System.out.println("Password from database = " + dbPassword);
                System.out.println("Password from user = " + password);
                System.out.println("passwords iguais: " + dbPassword.compareTo(password));

            }
//
            query = "SELECT salt FROM users WHERE username=?";
                        
            st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            rs = st.executeQuery();
            
            while (rs.next()) {                       
                salt = rs.getBytes(1);        
                System.out.println("Salt = " + salt);  
            }    
            String hashPassword = hashString(password,salt);     
//
            //Integer equals = dbPassword.compareTo(password); // 0 se sao iguais
            if((dbPassword.compareTo(hashPassword)) != 0){
                throw new WrongPasswordException();
            }
            else{
                 query = "DELETE FROM users WHERE username=?";
                    
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } catch(SQLException e){
                        System.out.println(e);
        
                }
        
                //apagar permissoes dos ficheiros deste user
                
                query = "SELECT filename FROM files WHERE fileowner=?";
        
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    rs = st.executeQuery();        
        
                    while(rs.next()) {                       
                        String fileName = rs.getString(1);        
                        System.out.println("Filename = " + fileName);
                        
                        query = "DELETE FROM permissions WHERE filename=?";
                                     
                        try {
                            st = connection.prepareStatement(query);
                            st.setString(1, fileName);
                        
                            st.executeUpdate();
                            st.close();
                        } catch(SQLException e){
                                System.out.println("deleting permissions of files belonging to deleted user" + e);
        
                        }
                    }
                }
                catch(Exception e){
                    System.out.println(e.toString());
                }

                //apagar permissoes deste user
                query = "DELETE FROM permissions WHERE username=?";
                            
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } catch(SQLException e){
                        System.out.println("deleting this users permissions" + e);
        
                }
        
                //apagar ficheiros deste user
                query = "DELETE FROM files WHERE fileowner=?";
                            
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } catch(SQLException e){
                        System.out.println("deleting files belonging to deleted user" + e);
        
                }

                deleteUserBackUp(userName);
            }
        } catch(SQLException e){
            System.out.println(e);
        }
      
    }


    public void deleteFile(String fileID, ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
       
        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        if(!verifyTimeStamp(timeStamp,publicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
        String hashMessageString = decrypt(publicKey, hashMessage.toByteArray());
        if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
       
        //enviar excecao para o user
        String cookie = decrypt(privateKey, cookie_bytes.toByteArray());
        
        String dbUserName = correspondentUser(cookie);

        if(checkFileOwner(fileID, dbUserName)){

            String query = "DELETE FROM files WHERE filename=?";
                        
            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, fileID);
            
                st.executeUpdate();
                System.out.println("The file " + fileID + " was deleted.");
                st.close();
            } 
            catch(SQLException e){
                    System.out.println("?????" + e);
            }

            //apagar permissoes associadas a este ficheiro
            query = "DELETE FROM permissions WHERE filename=?";
                        
            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, fileID);
            
                st.executeUpdate();
                st.close();
            } catch(SQLException e){
                    System.out.println("deleting this files permissions" + e);
            }
            
            deleteFileBackUp(fileID);
        }
        else{
            throw new WrongOwnerException(); //alterar esta excecao para recer delete/share
        }
    }
}

//para fazer servidor:
//funco que verifica os timestamps (<20 segundos?) - FEITO
//funcao que verifica integridade da mensagem -> verifica hash message - FEITO
//formatar (encriptar) respostas do servidor -> share e download
//criar coluna na tabela users para a public key do user (encriptada com a chave publica do servidor)
//criar 2 colunas na tabela das permissoes: chave simetrica (encriptada com a chave publica do cliente) e initialization vector (encriptado com a chave publica do cliente correspondente)
//onde esta chave publica do servidor ---> fazer query para ir buscar chave do cliente (quando esta estiver na bd)
//verifySystemState (para ver ataques) que verifica coluna hash em todas as tabelas e pode originar troca de servidores (promote)
//extra: comando "show files shared with me"

//para fazer cliente:
//Eduardo -> chave publica e chave privada + criar pasta Public Key + criar pasta Private Key (password protected cada)
//colocar no codigo a parte da chave simetrica
//formatar (encriptar) pedidos do cliente --> gerar timestamps, hashes
//receber respostas corretamente do servidor

//extra: verificar password (tamanho, carateres especiais...)