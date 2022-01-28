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

public class mainServer {
    
    ManagedChannel channel;
    MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub stub;
    boolean clientActive = false;
    private databaseAccess database;
    Connection connection;
    private String userName;
    private String password;
    private Key privateKey;
    private Key publicKey;
    private boolean hasKeys = false;

    public mainServer(String DBName, Boolean flag, ManagedChannel Channel, MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub Stub){
        if(flag){
            channel = Channel;
            stub = Stub;
            clientActive = true;
            System.out.println("Existent backup server. Connected.");
        }
        database = new databaseAccess(DBName);
        connection = database.connect();
    }

    /*------------------------------------ Database Functionss ------------------------------------------------*/

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

    public String getFileOwner(String fileName) throws Exception{

        String query = "SELECT fileowner FROM files WHERE filename=?";

 
        PreparedStatement st = connection.prepareStatement(query);
        st.setString(1, fileName);
    
        ResultSet rs = st.executeQuery();        

        if (rs.next()) {      

            return rs.getString(1);
        }
        throw new FileNotFoundException();
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

    public boolean checkIfUserExists(String userName){

        String query = "SELECT username FROM users WHERE username=?";
        
        try{
            PreparedStatement st = connection.prepareStatement(query);

            st.setString(1, userName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String user = rs.getString(1);        
                return true;
            }
            else{
                return false;
            }
        } catch(SQLException e){
            System.out.println(e);
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
                
                return true;
            }
            else{
                return false;
            }
        } 
        catch(SQLException e){
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

                if(userName.compareTo(dbUserName) == 0){
                    return true;
                }
            }
            else{
                return false;
            }
        } 
        catch(SQLException e){
            System.out.println(e);
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
                return true;
            }
            else{
                return false;
            }
        } 
        catch(SQLException e){
            System.out.println(e.toString());
        }
        
        return false;
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
                return dbUserName;
            }
            else
                throw new InvalidCookieException();
            
        } 
        catch(SQLException e){
                System.out.println(e);
        }

        return dbUserName;
    }

    
    /*------------------------------------ Database Integrity Functions------------------------------------------------*/

    public void verifyUsersTableStateDB() throws Exception{
        
        String query = "SELECT username, password, cookie, salt, publickey, hash FROM users";
        
        try{
            PreparedStatement st = connection.prepareStatement(query);
        
            ResultSet rs = st.executeQuery();        

            while(rs.next()) {                       
                String userName = rs.getString(1);
                String password = rs.getString(2);        
                String cookie = rs.getString(3);        
                byte[] salt = rs.getBytes(4);        
                byte[] publicKeyDB = rs.getBytes(5);        
                byte[] encryptedHashLineDB = rs.getBytes(6);       

                if(cookie == null)
                    cookie = "";
                String hashLineDB = Security.decrypt(publicKey, encryptedHashLineDB);
                String hashLine = Security.createUserHashDb(userName, password, cookie, salt, publicKeyDB);
                
                if(hashLineDB.compareTo(hashLine) != 0){ 
                    System.out.println("Error Error Error... Integrity of table users compromissed! Shutting Down...");
                    if(clientActive){
                        MainBackupServer.promoteRequest request = MainBackupServer.promoteRequest.newBuilder().build();
                        stub.promote(request);
                        throw new RansomwareAttackException();
                    }else
                        throw new FullRansomwareAttackException();
                }            
            }
        } 
        catch(SQLException e){
            System.out.println(e.toString());
        }
    }
    
    public void verifyFilesTableStateDB() throws Exception{
        
        String query = "SELECT filename, filecontent, fileowner, hash FROM files";
        
        try{
            PreparedStatement st = connection.prepareStatement(query);
        
            ResultSet rs = st.executeQuery();        

            while(rs.next()) {                       
                String fileName = rs.getString(1);
                byte[] fileContent = rs.getBytes(2);        
                String fileOwner = rs.getString(3);        
                byte[] encryptedHashLineDB = rs.getBytes(4);             
                
                String hashLineDB = Security.decrypt(publicKey, encryptedHashLineDB);
                String hashLine = Security.createFileHashDb(fileName, fileContent, fileOwner);
                
                if(hashLineDB.compareTo(hashLine) != 0){ 
                    System.out.println("Eror Error Error... Integrity of table files compromissed! Shutting down...");
                    if(clientActive){
                        MainBackupServer.promoteRequest request = MainBackupServer.promoteRequest.newBuilder().build();
                        stub.promote(request);
                        throw new RansomwareAttackException();
                    }else
                        throw new FullRansomwareAttackException();
                }            
            }
        } 
        catch(SQLException e){
            System.out.println(e.toString());
        }
    }

    public void verifyPermissionsTableStateDB() throws Exception{

        String query = "SELECT filename, username, symmetrickey, initializationvector, hash FROM permissions";
        
        try{
            PreparedStatement st = connection.prepareStatement(query);
        
            ResultSet rs = st.executeQuery();        

            while(rs.next()) {                       
                String fileName = rs.getString(1);
                String userName = rs.getString(2);     
                byte[] encryptedSymmetricKey = rs.getBytes(3);        
                byte[] encryptedInitializationVector = rs.getBytes(4);         
                byte[] encryptedHashLineDB = rs.getBytes(5);
      
                String hashLineDB = Security.decrypt(publicKey, encryptedHashLineDB);
                String hashLine = Security.createPermissionHashDb(fileName, userName, encryptedSymmetricKey, encryptedInitializationVector);
                
                if(hashLineDB.compareTo(hashLine) != 0){
                    System.out.println("Eror Error Error... Integrity of table permissions compromissed! Shutting down...");
                    if(clientActive){
                        MainBackupServer.promoteRequest request = MainBackupServer.promoteRequest.newBuilder().build();
                        stub.promote(request);
                        throw new RansomwareAttackException();
                    }else
                        throw new FullRansomwareAttackException();
                }            
            }
        } 
        catch(SQLException e){
            System.out.println(e.toString());
        }
    }

    /*------------------------------------User-MainServer Communication------------------------------------------------*/

    public void signUp(String username, ByteString password_bytes, ByteString publickeyClient, 
    ByteString timeStamp, ByteString hashMessage) throws Exception{
    
        System.out.println("User " + username + " has attempted to signup.");

        if(!hasKeys){
            privateKey = Security.getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = Security.getPublicKey("rsaPublicKey");
            hasKeys = true;
        }

        byte[] clientPubKeyArray = Security.decryptKey(publickeyClient.toByteArray(), privateKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key clientPubKey = keyFactory.generatePublic(keySpec);
        
        if(!Security.verifyTimeStamp(timeStamp, clientPubKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(password_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(publickeyClient.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        String hashMessageString = Security.decrypt(clientPubKey, hashMessage.toByteArray());
        if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }

        verifyUsersTableStateDB(); 
        
        String query = "SELECT username FROM users WHERE username=?"; 

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, username);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String name = rs.getString(1);        
                throw new ExistentUsernameException();
            }
            else{

                byte[] salt = Security.createSalt();
                String password = Security.decrypt(privateKey, password_bytes.toByteArray());
                String hashPassword = Security.hashString(password, salt);
                
                String hashUser = Security.createUserHashDb(username, hashPassword, "", salt, publickeyClient.toByteArray());
                byte[] encryptedHashUser = Security.encrypt(privateKey, hashUser.getBytes());

                query = "INSERT INTO users ("  
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
                st.setBytes(5, encryptedHashUser); 

                st.executeUpdate();
                st.close();
                if(clientActive)
                    sendUserToBackUp(username, Security.hashString(password, salt), salt, 
                    ByteString.copyFrom(publickeyClient.toByteArray()), ByteString.copyFrom(encryptedHashUser));
            }

        } catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
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
            privateKey = Security.getPrivateKey("src/main/java/pt/tecnico/grpc/server/rsaPrivateKey");
            publicKey = Security.getPublicKey("rsaPublicKey");
            hasKeys = true;
        }
        
        verifyUsersTableStateDB(); 

        String query = "SELECT publickey FROM users WHERE username=?";  
        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, username);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                userPublicKeyEncrypted = rs.getBytes(1);   
                userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted, privateKey);
                
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

        if(!Security.verifyTimeStamp(timeStamp, userPublicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(username.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(password_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

        if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }
        
        String password = Security.decrypt(privateKey, password_bytes.toByteArray());

        query = "SELECT username FROM users WHERE username=?";  

        try{
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, username);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                String user = rs.getString(1);                        

                query = "SELECT password FROM users WHERE username=?"; 

                try{
                    st = connection.prepareStatement(query);
                    st.setString(1, username);
                
                    rs = st.executeQuery();        
    
                    while (rs.next()) {                       
                        dbPassword = rs.getString(1);            
                    }
                    
                    query = "SELECT salt FROM users WHERE username=?";   
                    
                    st = connection.prepareStatement(query);
                    st.setString(1, username);
                
                    rs = st.executeQuery();
                    
                    while (rs.next()) {                       
                        salt = rs.getBytes(1);        
                    }    

                    String hashPassword = Security.hashString(password,salt); 
                    
                    if((dbPassword.compareTo(hashPassword)) != 0)  
                        throw new WrongPasswordException();
                    
                    else{
                        System.out.println("User " + username + " logged in.");
                    
                        String cookie = Security.createCookie(username, password);
                        String cookieHash = Security.hashString(cookie, new byte[0]);
                        
                        query = "UPDATE users SET cookie=? WHERE username=?";   
            
                        try {
                            st = connection.prepareStatement(query);
                            st.setString(1, cookieHash);
                            st.setString(2, username);
                        
                            st.executeUpdate();
                            st.close();
                        } 
                        catch(SQLException e){
                            System.out.println("Couldn't update cookie" + e);
                            throw new FailedOperationException();
                        }

                        String hashUser = Security.createUserHashDb(username, hashPassword, cookieHash, salt, userPublicKeyEncrypted);
                        byte[] hashUserEncrypted = Security.encrypt(privateKey, hashUser.getBytes());

                        query = "UPDATE users SET hash=? WHERE username=?";   
            
                        try {
                            st = connection.prepareStatement(query);
                            st.setBytes(1, hashUserEncrypted);
                            st.setString(2, username);
                        
                            st.executeUpdate();
                            st.close();
                        } 
                        catch(SQLException e){
                            System.out.println("Couldn't update cookie" + e);
                            throw new FailedOperationException();
                        }

                        if(clientActive)
                            updateCookieBackUp(username, Security.hashString(cookie, new byte[0]), ByteString.copyFrom(hashUserEncrypted));
                        
                        byte[] encryptedCookie = Security.encrypt(userPublicKey, cookie.getBytes()); 
                        String hashCookie = Security.hashString(cookie, new byte[0]);
                        byte[] encryptedHash = Security.encrypt(privateKey, hashCookie.getBytes());

                        UserMainServer.loginResponse response= UserMainServer.loginResponse.newBuilder()
                        .setCookie(ByteString.copyFrom(encryptedCookie)).setHashCookie(ByteString.copyFrom(encryptedHash)).build();

                        return response;
                    }
    
                } 
                catch(SQLException e){
                    System.out.println(e);
                    throw new FailedOperationException();
                }
            }
            else{
                throw new UserDoesNotExistException();
            }
        } 
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }
    
    public void logout(ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        try{
            verifyUsersTableStateDB();
            
            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());

            String dbUserName = correspondentUser(hashCookie);

            System.out.println("User " + dbUserName + " is logging out.");

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec);
            
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            String hashPassword = getUserPasswordDB(dbUserName);
            byte[] salt = getUserSaltDB(dbUserName);

            String hashUser = Security.createUserHashDb(dbUserName, hashPassword, "", salt, userPublicKeyEncrypted);
            byte[] hashUserEncrypted = Security.encrypt(privateKey, hashUser.getBytes());

            String query = "UPDATE users SET cookie=?, hash=? WHERE username=?";
                    
            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, "");
                st.setBytes(2, hashUserEncrypted);
                st.setString(3, dbUserName);
            
                st.executeUpdate();
                st.close();
            } 
            catch(SQLException e){
                System.out.println("Couldn't update cookie" + e);
                throw new FailedOperationException();
            }
            if(clientActive)
                updateCookieBackUp(dbUserName, "", ByteString.copyFrom(hashUserEncrypted));
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public UserMainServer.isUpdateResponse isUpdate(String fileID, ByteString cookie_bytes,
        ByteString timeStamp, ByteString hashMessage) throws Exception{

        try{
            Boolean isUpdate = false;
            
            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());

            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec);
            
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());
            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            byte[] encryptedSymmetricKey = new byte[0];
            byte[] initializationVector = new byte[0];

            if(checkIfFileExists(fileID) && checkIfUserAlreadyHasPermission(fileID, dbUserName)){ 
                System.out.println("File " + fileID + " already exists and user has permission to Update it.");
                isUpdate = true;
                encryptedSymmetricKey = getEncryptedSymmetricKeyDB(fileID, dbUserName);
                initializationVector = getInitializationVectorDB(fileID, dbUserName);
            }
                
            byte isUpdateByte = (byte)(isUpdate?1:0);
            ByteString encryptedSymmetricKeyByteString =  ByteString.copyFrom(encryptedSymmetricKey);
            ByteString initializationVectorByteString =  ByteString.copyFrom(initializationVector);
            ByteString encryptedTimeStampByteString = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

            ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();

            responseBytes.write(isUpdateByte);
            responseBytes.write(":".getBytes());
            responseBytes.write(encryptedSymmetricKey);
            responseBytes.write(":".getBytes());
            responseBytes.write(initializationVector);
            responseBytes.write(":".getBytes());
            responseBytes.write(encryptedTimeStampByteString.toByteArray());

            String hashResponse = Security.hashString(new String(responseBytes.toByteArray()),new byte[0]);
            ByteString encryptedHashResponse = ByteString.copyFrom(Security.encrypt(privateKey, hashResponse.getBytes()));
            
            UserMainServer.isUpdateResponse response = UserMainServer.isUpdateResponse.newBuilder()
            .setIsUpdate(isUpdate).setSymmetricKey(encryptedSymmetricKeyByteString)
            .setInitializationVector(initializationVectorByteString)
            .setTimeStamp(encryptedTimeStampByteString).setHashMessage(encryptedHashResponse).build();

            return response;
            
            
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public void upload(String fileID, ByteString cookie_bytes, ByteString file, ByteString symmetricKey, 
        ByteString initializationVector, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        try{
            verifyUsersTableStateDB();
            
            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());

            String dbUserName = correspondentUser(hashCookie);

            System.out.println("User " + dbUserName + " is uploading the file " + fileID);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
            
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
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
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            verifyPermissionsTableStateDB();
            verifyFilesTableStateDB();
               
            if(checkIfFileExists(fileID) && checkIfUserAlreadyHasPermission(fileID, dbUserName)){ 

                String ownerFile = getFileOwner(fileID);
                String hashFile = Security.createFileHashDb(fileID, file.toByteArray(), ownerFile);
                byte[] hashFileEncrypted = Security.encrypt(privateKey, hashFile.getBytes());
                
                String query = "UPDATE files SET filecontent=?, hash=? WHERE filename=?";   

                try {
                    PreparedStatement st = connection.prepareStatement(query);
                    st.setBytes(1, file.toByteArray());
                    st.setBytes(2, hashFileEncrypted);
                    st.setString(3, fileID);
                
                    st.executeUpdate();
                    st.close();
                } 
                catch(SQLException e){
                    System.out.println("Couldn't update fileContent" + e);
                    throw new FailedOperationException(); 
                }
                if(clientActive)
                    updateFileBackUp(fileID, file, ByteString.copyFrom(hashFileEncrypted));
                
                return;
            } 
            if(checkIfFileExists(fileID) && !checkIfUserAlreadyHasPermission(fileID, dbUserName))
                throw new DuplicateFileException(fileID);
                
            String hashFile = Security.createFileHashDb(fileID, file.toByteArray(), dbUserName);
            byte[] hashFileEncrypted = Security.encrypt(privateKey, hashFile.getBytes());
            
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
                st.setString(3, dbUserName);
                st.setBytes(4, hashFileEncrypted);

                st.executeUpdate();
                st.close();
            } 
            catch(SQLException e){
                System.out.println(e);
                throw new FailedOperationException();
            }

            if(clientActive)
                sendFileToBackUp(fileID, file, dbUserName, ByteString.copyFrom(hashFileEncrypted)); 

            String hashPermission = Security.createPermissionHashDb(fileID, dbUserName, symmetricKey.toByteArray(),
            initializationVector.toByteArray());
            byte[] hashPermissionEncrypted = Security.encrypt(privateKey, hashPermission.getBytes());

            query = "INSERT INTO permissions ("
            + " filename,"
            + " username,"
            + " symmetrickey,"
            + " initializationvector, "
            + " hash) VALUES ("
            + " ?, ?, ?, ?, ?)";

            try {
                PreparedStatement st = connection.prepareStatement(query);

                st.setString(1, fileID);
                st.setString(2, dbUserName);
                st.setBytes(3, symmetricKey.toByteArray());
                st.setBytes(4, initializationVector.toByteArray());
                st.setBytes(5, hashPermissionEncrypted);

                st.executeUpdate();
                st.close();
            } 
            catch(SQLException e){
                    System.out.println(e);
                    throw new FailedOperationException();
            }

            if(clientActive)
                sendPermissionToBackUp(fileID, dbUserName, ByteString.copyFrom(symmetricKey.toByteArray()), 
                ByteString.copyFrom(initializationVector.toByteArray()), ByteString.copyFrom(hashPermissionEncrypted));
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public UserMainServer.showFilesResponse showFiles(ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{

        try{

            verifyUsersTableStateDB();

            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());

            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec);
            
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            List<String> listOfFiles = new ArrayList<String>();

            String query = "SELECT filename FROM permissions WHERE username=?";

            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, dbUserName);
            
                ResultSet rs = st.executeQuery();        

                while (rs.next()) {      
                    String fileName = rs.getString(1);
                    listOfFiles.add(fileName);
                }
            } 
            catch(SQLException e){
                System.out.println(e);
            }

            ByteString encryptedTimeStampByteString = ByteString.copyFrom(Security.encrypt(privateKey, 
            Security.getTimeStampBytes()));

            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(listOfFiles.toString().getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedTimeStampByteString.toByteArray());

            String hashResponse = Security.hashString(new String(messageBytes.toByteArray()),new byte[0]);
            ByteString encryptedHashResponse = ByteString.copyFrom(Security.encrypt(privateKey, hashResponse.getBytes()));
            
            UserMainServer.showFilesResponse response = UserMainServer.showFilesResponse.newBuilder()
            .addAllFileName(listOfFiles).setTimeStamp(encryptedTimeStampByteString).setHashMessage(encryptedHashResponse).build();

            return response;
        }
        catch(SQLException e){
            System.out.println(e);
        }
        return null;
    }

    public UserMainServer.downloadResponse download(String fileID, ByteString cookie_bytes,
     ByteString timeStamp, ByteString hashMessage ) throws Exception{

        try{
            verifyUsersTableStateDB();
            
            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());
            String dbUserName = correspondentUser(hashCookie);

            System.out.println("User " + dbUserName + " is downloading the file " + fileID + ".");


            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
        
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            verifyPermissionsTableStateDB();
            verifyFilesTableStateDB();

            if(checkIfUserAlreadyHasPermission(fileID, dbUserName)){

                byte[] encryptedSymmetricKey = getEncryptedSymmetricKeyDB(fileID, dbUserName);
                byte[] encrypedFileContent = getEncryptedFileContentDB(fileID);
                byte[] initializationVector = getInitializationVectorDB(fileID, dbUserName);
                
                ByteString encryptedSymmetricKeyByteString =  ByteString.copyFrom(encryptedSymmetricKey);
                ByteString encryptedFileContentByteString = ByteString.copyFrom(encrypedFileContent);
                ByteString initializationVectorByteString =  ByteString.copyFrom(initializationVector);
                ByteString encryptedTimeStampByteString = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

                messageBytes = new ByteArrayOutputStream();
                messageBytes.write(encrypedFileContent);
                messageBytes.write(":".getBytes());
                messageBytes.write(encryptedSymmetricKey);
                messageBytes.write(":".getBytes());
                messageBytes.write(initializationVector);
                messageBytes.write(":".getBytes());
                messageBytes.write(encryptedTimeStampByteString.toByteArray());

                String hashResponse = Security.hashString(new String(messageBytes.toByteArray()),new byte[0]);
                ByteString encryptedHashResponse = ByteString.copyFrom(Security.encrypt(privateKey, hashResponse.getBytes()));
                
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

    public UserMainServer.shareResponse share(String fileID, ByteString cookie_bytes, 
    List<String> users, ByteString timeStamp, ByteString hashMessage) throws Exception{
    
        try{
            verifyUsersTableStateDB();
            
            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());
            String dbUserName = correspondentUser(hashCookie);

            System.out.println("User " + dbUserName + " is sharing the file " + fileID + ".");

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
        
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(users.toString().getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());
            
            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }
            
            verifyFilesTableStateDB(); 
            verifyPermissionsTableStateDB();         

            List<ByteString> listOfEncryptedPublicKeysByteString = new ArrayList<>();
            
            List<String> listOfWrongNames = new ArrayList<String>();
            List<String> listOfWrongNamesPermissions = new ArrayList<String>();
            
            if(checkIfFileExists(fileID)){
                if(checkFileOwner(fileID, dbUserName)){
                    for (String userName : users) {
                        if(checkIfUserExists(userName)){
                            if(!checkIfUserAlreadyHasPermission(fileID, userName)){

                                byte[] sharedUserPublicKeyEncrypted = getUserPublicKeyDB(userName);
                                byte[] sharedUserPublicKeyByteArray = Security.decryptKey(sharedUserPublicKeyEncrypted,privateKey); 
                                byte[] sharedUserEncryptedPublicKey = Security.encryptKey(sharedUserPublicKeyByteArray,userPublicKey); 
                                listOfEncryptedPublicKeysByteString.add(ByteString.copyFrom(sharedUserEncryptedPublicKey)); 
                            }
                            else{  
                                listOfWrongNamesPermissions.add(userName);
                            }
                        }
                        else{
                            listOfWrongNames.add(userName);
                        }
                    }
                }
                else{
                    throw new WrongOwnerException();  
                }
            }
            else{
                throw new FileUnknownException(fileID);     
            }

            byte[] encryptedSymmetricKey = getEncryptedSymmetricKeyDB(fileID, dbUserName);
                            
            ByteString encryptedSymmetricKeyByteString =  ByteString.copyFrom(encryptedSymmetricKey);
            ByteString encryptedTimeStampByteString = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));        
            
            ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
            responseBytes = new ByteArrayOutputStream();
            responseBytes.write(encryptedSymmetricKey);
            responseBytes.write(":".getBytes());
            for (ByteString encryptedPublicKey : listOfEncryptedPublicKeysByteString) {
                responseBytes.write(encryptedPublicKey.toByteArray());
                responseBytes.write(":".getBytes());
            }
            responseBytes.write(listOfWrongNames.toString().getBytes());
            responseBytes.write(":".getBytes());
            responseBytes.write(listOfWrongNamesPermissions.toString().getBytes());
            responseBytes.write(":".getBytes());
            responseBytes.write(encryptedTimeStampByteString.toByteArray());

            String hashResponse = Security.hashString(new String(responseBytes.toByteArray()),new byte[0]);

            ByteString encryptedHashResponse = ByteString.copyFrom(Security.encrypt(privateKey, hashResponse.getBytes()));            

            UserMainServer.shareResponse response = UserMainServer.shareResponse.newBuilder()
            .setSymmetricKey(encryptedSymmetricKeyByteString).addAllPublicKeys(listOfEncryptedPublicKeysByteString).
            addAllWrongUserName(listOfWrongNames).addAllWrongUserNamePermission(listOfWrongNamesPermissions).setTimeStamp(encryptedTimeStampByteString).
            setHashMessage(encryptedHashResponse).build();

            return response;  
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public void shareKey(ByteString cookie_bytes,List<ByteString> symmetricKeyList,
        List<String> userNameList, String fileID, 
        ByteString timeStamp, ByteString hashMessage) throws Exception{

        String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());
        String dbUserName = correspondentUser(hashCookie);

        byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
        byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key userPublicKey = keyFactory.generatePublic(keySpec); 
        
        byte[] initializationVector = getInitializationVectorDB(fileID, dbUserName);

        if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
            throw new TimestampException();

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(cookie_bytes.toByteArray());
        messageBytes.write(":".getBytes());
        for (ByteString symmetricKey : symmetricKeyList) {
            messageBytes.write(symmetricKey.toByteArray());
            messageBytes.write(":".getBytes());
        }
        messageBytes.write(userNameList.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(timeStamp.toByteArray());

        String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

        if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
            throw new MessageIntegrityException();
        }

        int counter = 0;
        if(checkIfFileExists(fileID)){
            if(checkFileOwner(fileID, dbUserName)){
                for (String userName : userNameList) { 
                    if(checkIfUserExists(userName)){
                        if(!checkIfUserAlreadyHasPermission(fileID, userName)){
                            
                            byte[] encryptedSymmetricKey = symmetricKeyList.get(counter).toByteArray();
                            String hashPermission = Security.createPermissionHashDb(fileID, userName, encryptedSymmetricKey,initializationVector);
                            byte[] hashPermissionEncrypted = Security.encrypt(privateKey, hashPermission.getBytes());

                            String query = "INSERT INTO permissions ("
                            + " filename,"
                            + " username,"
                            + " symmetrickey,"
                            + " initializationvector, "
                            + " hash) VALUES ("
                            + " ?, ?, ?, ?, ?)";

                            try {
                                PreparedStatement st = connection.prepareStatement(query);

                                st.setString(1, fileID);
                                st.setString(2, userName);
                                st.setBytes(3, encryptedSymmetricKey);
                                st.setBytes(4, initializationVector);
                                st.setBytes(5, hashPermissionEncrypted);
                               
                                st.executeUpdate();
                                st.close();

                                counter++;
                            } 
                            catch(SQLException e){
                                    System.out.println(e);
                                    throw new FailedOperationException();
                            }
                            if(clientActive){
                                sendPermissionToBackUp(fileID, userName, ByteString.copyFrom(encryptedSymmetricKey),
                                ByteString.copyFrom(initializationVector), ByteString.copyFrom(hashPermissionEncrypted));
                            }
                        }
                        else
                            throw new UserAlreadyHasAccessException(userName);
                    }
                    else
                        throw new UserUnknownException(userName);
                }
            }
            else
                throw new WrongOwnerException();  
        }
        else
            throw new FileUnknownException(fileID);  
    }

    public UserMainServer.unshareResponse unshare(String fileID, ByteString cookie_bytes, List<String> users, 
    ByteString timeStamp, ByteString hashMessage) throws Exception{ 
        
        try{
            verifyUsersTableStateDB(); 

            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());
            String dbUserName = correspondentUser(hashCookie);

            System.out.println("User " + dbUserName + " is unsharing the file " + fileID + ".");

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 
        
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(users.toString().getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());

            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());
            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            verifyPermissionsTableStateDB();
            verifyFilesTableStateDB(); 
            
            List<String> listOfWrongNames = new ArrayList<String>();
            List<String> listOfWrongNamesPermissions = new ArrayList<String>();

            if(checkIfFileExists(fileID)){
                if(checkFileOwner(fileID, dbUserName)){
                    for (String userName : users) {
                        if(checkIfUserExists(userName)){
                            if(checkIfUserAlreadyHasPermission(fileID, userName) && !checkFileOwner(fileID, userName)){
                                
                                String query = "DELETE FROM permissions WHERE filename=? AND username=?";
                        
                                try {
                                    PreparedStatement st = connection.prepareStatement(query);
                                    st.setString(1, fileID);
                                    st.setString(2, userName);
                                
                                    st.executeUpdate();
                                    st.close();
                                } 
                                catch(SQLException e){
                                        System.out.println(e);
                                        throw new FailedOperationException();
                                }
                                if(clientActive)
                                    removePermissionFromBackUp(fileID, userName);
                            }
                            else{
                                listOfWrongNamesPermissions.add(userName);
                            }
                        }
                        else{
                            listOfWrongNames.add(userName);
                        }
                    }
                }
                else
                    throw new WrongOwnerUnshareException();  
            }
            else
                throw new FileUnknownException(fileID);
        
        ByteString encryptedTimeStampByteString = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes = new ByteArrayOutputStream();
        
        responseBytes.write(listOfWrongNames.toString().getBytes());
        responseBytes.write(":".getBytes());
        responseBytes.write(listOfWrongNamesPermissions.toString().getBytes());
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteString.toByteArray());

        String hashResponse = Security.hashString(new String(responseBytes.toByteArray()),new byte[0]);

        ByteString encryptedHashResponse = ByteString.copyFrom(Security.encrypt(privateKey, hashResponse.getBytes()));

        UserMainServer.unshareResponse response = UserMainServer.unshareResponse.newBuilder().
        addAllWrongUserName(listOfWrongNames).addAllWrongUserNamePermission(listOfWrongNamesPermissions).setTimeStamp(encryptedTimeStampByteString).
        setHashMessage(encryptedHashResponse).build();

        return response;  
        }
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }
        
    public void deleteUser(String userName, ByteString password_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        try{
            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(userName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec); 

            System.out.println("Deleting user " + userName + ".");
            
            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(userName.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(password_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());

            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());
            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }
            
            verifyUsersTableStateDB(); 
            verifyFilesTableStateDB(); 
            verifyPermissionsTableStateDB(); 

            String password = Security.decrypt(privateKey, password_bytes.toByteArray());
            byte[] salt = new byte[0];
            
            String query = "SELECT password FROM users WHERE username=?";
            String dbPassword = "";
            
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            ResultSet rs = st.executeQuery();        

            if(rs.next()) {                       
                dbPassword = rs.getString(1);        
                
                System.out.println("Password from database = " + dbPassword);
                System.out.println("Password from user = " + password);
                System.out.println("passwords iguais: " + dbPassword.compareTo(password));
            }

            query = "SELECT salt FROM users WHERE username=?";
                        
            st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            rs = st.executeQuery();
            
            while (rs.next()) {                       
                salt = rs.getBytes(1);        
                System.out.println("Salt = " + salt);  
            }    
            String hashPassword = Security.hashString(password,salt);     
            
            if((dbPassword.compareTo(hashPassword)) != 0)
                throw new WrongPasswordException();
            
            else{
                query = "DELETE FROM users WHERE username=?";
                    
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } 
                catch(SQLException e){
                    System.out.println(e);
                    throw new FailedOperationException();
                }
        
                query = "SELECT filename FROM files WHERE fileowner=?";
        
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, userName);
                
                    rs = st.executeQuery();        
        
                    while(rs.next()) {                       
                        String fileName = rs.getString(1);        
                        
                        query = "DELETE FROM permissions WHERE filename=?";
                                    
                        try {
                            st = connection.prepareStatement(query);
                            
                            st.setString(1, fileName);
                        
                            st.executeUpdate();
                            st.close();
                        } 
                        catch(SQLException e){
                            throw new FailedOperationException();
                        }
                    }
                }
                catch(Exception e){
                    System.out.println(e);
                    throw new FailedOperationException();
                }

                query = "DELETE FROM permissions WHERE username=?";
                            
                try {
                    st = connection.prepareStatement(query);

                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } 
                catch(SQLException e){
                    throw new FailedOperationException();
                }
        
                query = "DELETE FROM files WHERE fileowner=?";
                            
                try {
                    st = connection.prepareStatement(query);

                    st.setString(1, userName);
                
                    st.executeUpdate();
                    st.close();
                } 
                catch(SQLException e){
                    throw new FailedOperationException();
                }
                if(clientActive)
                    deleteUserBackUp(userName);
            }
        } 
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }

    public void deleteFile(String fileID, ByteString cookie_bytes, ByteString timeStamp, ByteString hashMessage) throws Exception{
        
        try{
            verifyUsersTableStateDB(); 

            String hashCookie = Security.decrypt(privateKey, cookie_bytes.toByteArray());

            String dbUserName = correspondentUser(hashCookie);

            byte[] userPublicKeyEncrypted = getUserPublicKeyDB(dbUserName);
            byte[] userPublicKeyByteArray = Security.decryptKey(userPublicKeyEncrypted,privateKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(userPublicKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key userPublicKey = keyFactory.generatePublic(keySpec);

            System.out.println("Deleting file " + fileID + ".");

            if(!Security.verifyTimeStamp(timeStamp,userPublicKey))
                throw new TimestampException();

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(fileID.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(cookie_bytes.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(timeStamp.toByteArray());

            String hashMessageString = Security.decrypt(userPublicKey, hashMessage.toByteArray());

            if(!Security.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                throw new MessageIntegrityException();
            }

            verifyFilesTableStateDB(); 
            verifyPermissionsTableStateDB(); 

            if(checkIfFileExists(fileID)){
                if(checkFileOwner(fileID, dbUserName)){

                    String query = "DELETE FROM files WHERE filename=?";     

                    try {
                        PreparedStatement st = connection.prepareStatement(query);

                        st.setString(1, fileID);
                    
                        st.executeUpdate();
                        st.close();
                    } 
                    catch(SQLException e){
                        System.out.println(e);
                    }

                    query = "DELETE FROM permissions WHERE filename=?";         

                    try {
                        PreparedStatement st = connection.prepareStatement(query);

                        st.setString(1, fileID);
                    
                        st.executeUpdate();
                        st.close();
                    } 
                    catch(SQLException e){
                            System.out.println(e);
                    }
                    
                    if(clientActive)
                        deleteFileBackUp(fileID);
                }
                else
                    throw new WrongOwnerDeleteException(); 
            }
            else
                throw new FileUnknownException(fileID);

        } 
        catch(SQLException e){
            System.out.println(e);
            throw new FailedOperationException();
        }
    }


    /*---------------------------Main-BackupServer communication----------------------------------*/

    public void sendUserToBackUp(String username, String hashPassword, byte[] salt, ByteString publicKey, ByteString hash){

        try{
            ByteString saltByteString = ByteString.copyFrom(salt);

            MainBackupServer.writeUserRequest request = MainBackupServer.writeUserRequest.newBuilder().setUsername(username).
            setHashPassword(hashPassword).setSalt(saltByteString).
            setPublicKey(publicKey).setHash(hash).build();

            MainBackupServer.writeUserResponse response = stub.writeUser(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }


    public void sendPermissionToBackUp(String fileName, String userName, ByteString symmetricKey, ByteString initializationVector, ByteString hash){
        
        try{
            MainBackupServer.writePermissionRequest request = MainBackupServer.writePermissionRequest.newBuilder().setFileName(fileName)
            .setUserName(userName).setSymmetricKey(symmetricKey).setInitializationVector(initializationVector).
            setHash(hash).build();

            MainBackupServer.writePermissionResponse response = stub.writePermission(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }

    public void removePermissionFromBackUp(String fileName, String userName){

        try{

            MainBackupServer.removePermissionRequest request = MainBackupServer.removePermissionRequest.newBuilder().setFileName(fileName)
            .setUserName(userName).build();

            MainBackupServer.removePermissionResponse response = stub.removePermission(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }

    public void sendFileToBackUp(String filename, ByteString filecontent,  String fileowner, ByteString hash){
        
        try{
            MainBackupServer.writeFileRequest request = MainBackupServer.writeFileRequest.newBuilder().setFileName(filename).
            setFileContent(filecontent).setFileOwner(fileowner).setHash(hash).build();

            MainBackupServer.writeFileResponse response = stub.writeFile(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }
    
    public void updateCookieBackUp(String userName, String cookie, ByteString hash){
        
        try{
            MainBackupServer.updateCookieRequest request = MainBackupServer.updateCookieRequest.newBuilder().
            setUserName(userName).setCookie(cookie).setHash(hash).build();

            MainBackupServer.updateCookieResponse response = stub.updateCookie(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }

    public void updateFileBackUp(String fileName, ByteString fileContent, ByteString hash){
       
        try{
            MainBackupServer.updateFileRequest request = MainBackupServer.updateFileRequest.newBuilder().
            setFileName(fileName).setFileContent(fileContent).setHash(hash).build();

            MainBackupServer.updateFileResponse response = stub.updateFile(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }
   
    public void deleteFileBackUp(String fileName){
        
        try{
            MainBackupServer.deleteFileRequest request = MainBackupServer.deleteFileRequest.newBuilder().setFileName(fileName).build();

            MainBackupServer.deleteFileResponse response = stub.deleteFile(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }

    public void deleteUserBackUp(String userName){
       
        try{
            MainBackupServer.deleteUserRequest request = MainBackupServer.deleteUserRequest.newBuilder().setUserName(userName).build();

            MainBackupServer.deleteUserResponse response = stub.deleteUser(request);
        }
        catch(StatusRuntimeException e){
            if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){
                System.out.println("Ransmomware attack detected in Backup.");
			    clientActive = false;
                return;
			}
            System.out.println(e);
        }
    }
}
