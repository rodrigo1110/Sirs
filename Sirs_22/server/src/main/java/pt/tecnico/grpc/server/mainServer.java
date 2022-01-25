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


    public byte[] getUserPublicKeyDB(String userName) throws Exception{

        String query = "SELECT publickey FROM users WHERE username=?"; 

        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, userName);
        
        ResultSet rs = st.executeQuery();        

        if(rs.next())                       
            return rs.getBytes(1);   
        throw new UserUnknownException(userName);

    }
          
    
    
    public String getUserPasswordDB(String userName) throws Exception{

        String query = "SELECT password FROM users WHERE username=?"; 
        
        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, userName);
        
        ResultSet rs = st.executeQuery();        

        if(rs.next()) {                       
            return rs.getString(1);   
        }
        throw new UserUnknownException(userName);
    }

    

    public byte[] getUserSaltDB(String userName) throws Exception{

        String query = "SELECT salt FROM users WHERE username=?"; 

        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, userName);
    
        ResultSet rs = st.executeQuery();        

        if(rs.next()) {                       
            return rs.getBytes(1);   
        }
        throw new UserUnknownException(userName);
    }

    public byte[] getEncryptedFileContentDB(String fileName) throws Exception{

        String query = "SELECT filecontent FROM files WHERE filename=?";

 
        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, fileName);
    
        ResultSet rs = st.executeQuery();        

        if (rs.next()) {      

            return rs.getBytes(1);
        }
        throw new FileNotFoundException();
    }
    
    public byte[] getEncryptedSymmetricKeyDB(String fileName, String userName) throws Exception{

        String query = "SELECT symmetrickey FROM permissions WHERE filename=? AND username=?";

 
        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, fileName);
        st.setString(2, userName);
    
        ResultSet rs = st.executeQuery();        

        if (rs.next()) {      

            return rs.getBytes(1);
        }
        throw new EncryptedSymmetricKeyNotFoundException();
    }

    public byte[] getInitializationVectorDB(String fileName, String userName) throws Exception{

        String query = "SELECT initializationvector FROM permissions WHERE filename=? AND username=?";

 
        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, fileName);
        st.setString(2, userName);
    
        ResultSet rs = st.executeQuery();        

        if (rs.next()) {      

            return rs.getBytes(1);
        }
        throw new EncryptedInitializationVectorNotFoundException();
    }



/*         PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, userName);
    
        ResultSet rs = st.executeQuery();        

        if(rs.next()) {                       
            return rs.getBytes(1);   
        }
        throw new UserUnknownException(userName); */
    


    
    //---------------------------Hash Functions----------------------------------




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

    public String convertToHex(byte[] messageDigest) {
        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);
        return hexText;
    }
    
    public byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      byte[] salt = new byte[20];
    
      random.nextBytes(salt);
      return salt;
    }


    public String createUserHashDb(String username, String hashPassword, String hashCookie, 
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


    public String createFileHashDb(String fileID, byte[] fileContent, String fileOwner) throws Exception{

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileContent);
        messageBytes.write(":".getBytes());
        messageBytes.write(fileOwner.getBytes());
       
        byte[] message = messageBytes.toByteArray();
        return hashString(new String(message), new byte[0]);
    }


    public String createPermissionHashDb(String fileID, String username, byte[] encryptedSymmetricKey, 
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




    public boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
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
        if((timeStampLong - sentTimeStampLong) < 32000000)
            return true;
        return false;
    }


    public byte[] getTimeStampBytes(){
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();
        return Long.toString(timeStampLong).getBytes();
    }





    //---------------------------Encryption/Decryption Functions----------------------------------





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






    //------------------------------------Client-MainServer communication------------------------------------------------



    

    public void signUp(String username, ByteString password_bytes, ByteString publickeyClient, ByteString timeStamp, ByteString hashMessage) throws Exception{
    
        System.out.println("User " + username + " has attempted to signup.");

        if(!hasKeys){
            privateKey = getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = getPublicKey("rsaPublicKey");
            hasKeys = true;
        }

        byte[] clientPubKeyArray = decryptKey(publickeyClient.toByteArray(), privateKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key clientPubKey = keyFactory.generatePublic(keySpec);
        
        
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
        //byte[] encryptedHashMessage = encrypt(publicKey, hashMessageString.getBytes());

        System.out.println("HERE HERE HERE!");

        
        String query = "SELECT username FROM users WHERE username=?";  //Chech if username exists

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
                System.out.println("Else Else Else");

                byte[] salt = createSalt();
                String password = decrypt(privateKey, password_bytes.toByteArray());
                System.out.println("Password: " + password);
                String hashPassword = hashString(password, salt);
                System.out.println("Hash Password signup: " + hashPassword);
                
                String hashUser = createUserHashDb(username, hashPassword, "", salt, publickeyClient.toByteArray());
                byte[] encryptedHashUser = encrypt(privateKey, hashUser.getBytes());


                System.out.println("AQUI AQUI AQUI");

                query = "INSERT INTO users ("   //Insert new user in db table users
                + " username,"
                + " password, "
                + " salt, "
                + " publickey, "
                + " hash ) VALUES (" 
                + "?, ?, ?, ?, ?)";
                
            
                st = connection.prepareStatement(query);
                st.setString(1, username);
                st.setString(2, hashPassword);
                st.setBytes(3, salt);
                st.setBytes(4, publickeyClient.toByteArray());
                st.setBytes(5, encryptedHashUser); //alterado!!!!

                st.executeUpdate();
                st.close();

                sendUserToBackUp(username, hashString(password, salt), salt);
            }

        } catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }



    public String createCookie(String userName, String password) throws NoSuchAlgorithmException, NoSuchProviderException{
      
        String hexSalt = convertToHex(createSalt());
        //String salt_string = new String(createSalt(), StandardCharsets.UTF_8);

        String cookie = userName + password + hexSalt;
        System.out.println("bolacha: " + cookie);
        return cookie;
    }



    public UserMainServer.loginResponse login(String username, ByteString password_bytes, 
        ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        byte[] salt = new byte[0];
        String dbPassword = "";
        Key userPublicKey = null;
        byte[] userPublicKeyEncrypted = new byte[0];
        byte[] userPublicKeyByteArray = new byte[0];

        System.out.println("User " + username + " has attempted to login with password " + password + ".");

        if(!hasKeys){
            privateKey = getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = getPublicKey("rsaPublicKey");
            hasKeys = true;
        }
        

        String query = "SELECT publickey FROM users WHERE username=?";  // Get user public key
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, username);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                userPublicKeyEncrypted = rs.getBytes(1);   
                System.out.println("User public key: " + userPublicKeyEncrypted);
                userPublicKeyByteArray = decryptKey(userPublicKeyEncrypted, privateKey);
                
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                userPublicKey = keyFactory.generatePublic(keySpec);
            }
            else{
                throw new UserDoesNotExistException();
            }
        } catch(UserDoesNotExistException ex){
            throw new UserDoesNotExistException();
        } catch(Exception e){
            System.out.println(e);
        }    



        if(!verifyTimeStamp(timeStamp, userPublicKey))
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

            //check if user is registered
            query = "SELECT username FROM users WHERE username=?";  //Verify if user Exists
            try{
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, username);
            
                ResultSet rs = st.executeQuery();        

                if(rs.next()) {                       
                    String user = rs.getString(1);        
                    
                    System.out.println("O user existe " + user);
                    

                    query = "SELECT password FROM users WHERE username=?";  //get user password 

                    try {
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                    
                        rs = st.executeQuery();        
        
                        while (rs.next()) {                       
                            dbPassword = rs.getString(1);        
                            
                            System.out.println("Password from database = " + dbPassword);
                            System.out.println("Password from user = " + password);
        
                        }

                        
                        query = "SELECT salt FROM users WHERE username=?";   //get salt for hash calcultion
                        
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                    
                        rs = st.executeQuery();
                        
                        while (rs.next()) {                       
                            salt = rs.getBytes(1);        
                            System.out.println("Salt = " + salt);  
                        }    

                        String hashPassword = hashString(password,salt); 
                        
                                       
                        System.out.println("HashPasswordAfter: " + hashPassword);

                        
                        if((dbPassword.compareTo(hashPassword)) != 0)   //check if password is correct
                            throw new WrongPasswordException();
                        
                        else{
                            System.out.println("User " + username + " logged in with password " + password + ".");
                        
                            String cookie = createCookie(username, password);
                            String cookieHash = hashString(cookie, new byte[0]);

                            
                            query = "UPDATE users SET cookie=? WHERE username=?";   //criar/atualizar cookie na base de dados
                
                            try {
                                st = connection.prepareStatement(query);
                                st.setString(1, cookieHash);
                                st.setString(2, username);
                            
                                st.executeUpdate();
                                st.close();
                            } catch(SQLException e){
                                System.out.println("Couldn't update cookie" + e);
                                throw new FailedOperationException();
                            }

                            String hashUser = createUserHashDb(username, hashPassword, cookieHash, salt, userPublicKeyByteArray);
                            byte[] hashUserEncrypted = encrypt(privateKey, hashUser.getBytes());

                            query = "UPDATE users SET hash=? WHERE username=?";   ///atualizar hash user
                
                            try {
                                st = connection.prepareStatement(query);
                                st.setBytes(1, hashUserEncrypted);
                                st.setString(2, username);
                            
                                st.executeUpdate();
                                st.close();
                            } catch(SQLException e){
                                System.out.println("Couldn't update cookie" + e);
                                throw new FailedOperationException();
                            }

                            updateCookieBackUp(username, hashString(cookie, new byte[0]));


                            
                            byte[] encryptedCookie = encrypt(userPublicKey, cookie.getBytes()); //Preparar a resposta
                            String hashCookie = hashString(cookie, new byte[0]);
                            byte[] encryptedHash = encrypt(privateKey, hashCookie.getBytes());

                            UserMainServer.loginResponse response= UserMainServer.loginResponse.newBuilder()
			                .setCookie(ByteString.copyFrom(encryptedCookie)).setHashCookie(ByteString.copyFrom(encryptedHash)).build();
                            return response;
                        }
        
                        } catch(SQLException e){
                            System.out.println(e);
                            throw new FailedOperationException();
                        }
                }
                else{
                    throw new UserDoesNotExistException();
                }
            } catch(SQLException e){
                System.out.println(e.toString());
                throw new FailedOperationException();
            }
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
        try{
            String hashCookie = decrypt(privateKey, cookie_bytes.toByteArray());
            System.out.println("Decrypted hash of cookie: " + hashCookie);
            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec);
            
            
            if(!verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

                
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = decrypt(userPublicKey, hashMessage.toByteArray());
            if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }
            

            String hashPassword = getUserPasswordDB(dbUserName);
            byte[] salt = getUserSaltDB(dbUserName);

            String hashUser = createUserHashDb(dbUserName, hashPassword, hashCookie, salt, userPublicKeyEncrypted);
            byte[] hashUserEncrypted = encrypt(privateKey, hashUser.getBytes());

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
                throw new FailedOperationException();
            }
            
            updateCookieBackUp(dbUserName, "");
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }


    public void upload(String fileID, ByteString cookie_bytes, ByteString file, ByteString symmetricKey, 
                        ByteString initializationVector, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        try{
            String hashCookie = decrypt(privateKey, cookie_bytes.toByteArray());
            System.out.println("Decrypted hash of cookie: " + hashCookie);
            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
            
            
            if(!verifyTimeStamp(timeStamp,userPublicKey))
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
            messageBytes.write(initializationVector.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            
            String hashMessageString = decrypt(userPublicKey, hashMessage.toByteArray());
            if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }
            
/*             if(checkIfFileExists(fileID) && checkIfUserAlreadyHasPermission(fileID, dbUserName)){    //ADD flag to share response along with symmetric key
                                                                                                        // and iv
                String hashFile = createFileHashDb(fileID, file.toByteArray(), dbUserName);
                byte[] hashFileEncrypted = encrypt(privateKey, hashFile.getBytes());
                
                String query = "UPDATE files SET filecontent=?, hash=? WHERE filename=?";   //criar/atualizar cookie na base de dados
            
                try {
                    PreparedStatement st = connection.prepareStatement(query);
                    st.setBytes(1, file.toByteArray());
                    st.setBytes(2, hashFileEncrypted);
                    st.setString(3, fileID);
                
                    st.executeUpdate();
                    st.close();
                } catch(SQLException e){
                    System.out.println("Couldn't update cookie" + e);
                    throw new FailedOperationException();
                }
            } */
                
            //createFileChecksum(file.toByteArray()); 

            String hashFile = createFileHashDb(fileID, file.toByteArray(), dbUserName);
            byte[] hashFileEncrypted = encrypt(privateKey, hashFile.getBytes());
            

            String query = "INSERT INTO files ("
            + " filename,"
            + " filecontent,"
            + " fileowner,"
            + " hash ) VALUES ("
            + "?, ?, ?, ?)";

            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, fileID);
                st.setBytes(2, file.toByteArray());
                System.out.println("dbUserName no upload no fileowner " + dbUserName);
                st.setString(3, dbUserName);
                st.setBytes(4, hashFileEncrypted);

            
                st.executeUpdate();
                st.close();
            } catch(SQLException e){
                System.out.println(e);
                throw new FailedOperationException();
            }

            sendFileToBackUp(fileID, file, dbUserName);
            // add owner to permissions table

            String hashPermission = createPermissionHashDb(fileID, dbUserName, symmetricKey.toByteArray(),initializationVector.toByteArray());
            byte[] hashPermissionEncrypted = encrypt(privateKey, hashFile.getBytes());

            query = "INSERT INTO permissions ("
            + " filename,"
            + " username,"
            + " symmetrickey,"
            + " initializationvector, "
            + " hash) VALUES ("
            + " ?, ?, ?, ?, ?)";

            try {
                System.out.println("dbUserName no upload nas permisssoes " + dbUserName);
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, fileID);
                st.setString(2, dbUserName);
                st.setBytes(3, symmetricKey.toByteArray());
                st.setBytes(4, initializationVector.toByteArray());
                st.setBytes(5, hashPermissionEncrypted);


            
                st.executeUpdate();
                st.close();
            } catch(SQLException e){
                    System.out.println("wwwww" + e);
                    throw new FailedOperationException();

            }

            sendPermissionToBackUp(fileID, dbUserName);
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public String correspondentUser(String hashCookie) throws Exception{

        String dbUserName = "";

        if (hashCookie.length() == 0)
            throw new InvalidCookieException();
        

        String query = "SELECT username FROM users WHERE cookie=?";


        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, hashCookie);
        
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

        try{
            String hashCookie = decrypt(privateKey, cookie_bytes.toByteArray());
            System.out.println("Decrypted hash of cookie: " + hashCookie);
            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
        
        
            if(!verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            //esta publicKey (do cliente) tem de ir ser retirada da bd!!!!!
            String hashMessageString = decrypt(userPublicKey, hashMessage.toByteArray());
            if(!verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }


            
            System.out.println("Username no download: " + dbUserName);


            
            if(checkIfUserAlreadyHasPermission(fileID, dbUserName)){
                byte[] encryptedSymmetricKey = getEncryptedSymmetricKeyDB(fileID, dbUserName);
                byte[] encrypedFileContent = getEncryptedFileContentDB(fileID);
                byte[] initializationVector = getInitializationVectorDB(fileID, dbUserName);
                
                ByteString encryptedSymmetricKeyByteString =  ByteString.copyFrom(encryptedSymmetricKey);
                ByteString encryptedFileContentByteString = ByteString.copyFrom(encrypedFileContent);
                ByteString initializationVectorByteString =  ByteString.copyFrom(initializationVector);
                ByteString encryptedTimeStampByteString = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));


                messageBytes = new ByteArrayOutputStream();
                messageBytes.write(encrypedFileContent);
                messageBytes.write(":".getBytes());
                messageBytes.write(encryptedSymmetricKey);
                messageBytes.write(":".getBytes());
                messageBytes.write(initializationVector);
                messageBytes.write(":".getBytes());
                messageBytes.write(encryptedTimeStampByteString.toByteArray());

                String hashResponse = hashString(new String(messageBytes.toByteArray()),new byte[0]);
                ByteString encryptedHashResponse = ByteString.copyFrom(encrypt(privateKey, hashResponse.getBytes()));
                
                
                UserMainServer.downloadResponse response = UserMainServer.downloadResponse.newBuilder()
                .setFileContent(encryptedFileContentByteString).setKey(encryptedSymmetricKeyByteString)
                .setInitializationVector(initializationVectorByteString). 
                setTimeStamp(encryptedTimeStampByteString).setHashMessage(encryptedHashResponse).build();

                return response;
                        
            }
            else{
                throw new NotSharedWithUserException();
            }
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
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



    //---------------------------Main-BackupServer communication----------------------------------
    // add flag and verification in every function to check if there is a backup server alive before trying to communicate with him




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