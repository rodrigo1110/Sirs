package pt.tecnico.grpc.server;

import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.server.exceptions.BackupRansomwareAttackException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.nio.file.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;

import javax.crypto.Cipher;
import javax.lang.model.util.ElementScanner6;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;

import com.google.protobuf.ByteString;


public class backupServer {

    private boolean hasPublicKey = false;
    private Key serverPublicKey;
    private databaseAccess database = new databaseAccess("rdabackup");
    Connection connection = database.connect();
    
    //--------------------------mainServer-backupServer implementation--------------------------
    
    //----------------------TO DO: add correct exceptions later------------------------

    public String greet(String name){
        return "Hello " + name + ". I am instance number ";
    }


    public static Key getPublicKey(String filename) throws Exception {
    
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
    
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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

                System.out.println("userName: " + userName);  
                System.out.println("password: " + password);  
                System.out.println("cookie: " + cookie);  
                System.out.println("salt: " + convertToHex(salt));  
                System.out.println("publicKeyDB: " + convertToHex(publicKeyDB));  
                System.out.println("encryptedHashLineDB: " + convertToHex(encryptedHashLineDB));  

                if(cookie == null)
                    cookie = "";
                String hashLineDB = decrypt(serverPublicKey, encryptedHashLineDB);
                String hashLine = createUserHashDb(userName, password, cookie, salt, publicKeyDB);
                
                if(hashLineDB.compareTo(hashLine) != 0){ //change this verification for ==0  for testing ransomware attack in backup
                    System.out.println("Error Error Error... Integrity of table users compromissed! Shutting Down Backup...");
                    throw new BackupRansomwareAttackException();
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
                
                String hashLineDB = decrypt(serverPublicKey, encryptedHashLineDB);
                String hashLine = createFileHashDb(fileName, fileContent, fileOwner);
                
                if(hashLineDB.compareTo(hashLine) != 0){
                    System.out.println("Eror Error Error... Integrity of table files compromissed! Shutting down Backup...");
                    throw new BackupRansomwareAttackException();
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
      
                String hashLineDB = decrypt(serverPublicKey, encryptedHashLineDB);
                String hashLine = createPermissionHashDb(fileName, userName, encryptedSymmetricKey, encryptedInitializationVector);
                
                if(hashLineDB.compareTo(hashLine) != 0){
                    System.out.println("Eror Error Error... Integrity of table permissions compromissed! Shutting down...");
                    throw new BackupRansomwareAttackException();
                }            
            }
        } 
        catch(SQLException e){
            System.out.println(e.toString());
        }
    }






    public void writeFile(String fileName, ByteString fileContent, String fileOwner, ByteString hash) throws Exception{

        verifyFilesTableStateDB();

        String query = "INSERT INTO files ("
        + " filename,"
        + " filecontent,"
        + " fileowner,"
        + " hash ) VALUES ("
        + "?, ?, ?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
            st.setBytes(2, fileContent.toByteArray());
            st.setString(3, fileOwner);
            st.setBytes(4, hash.toByteArray());

            st.executeUpdate();
            st.close();
        } catch(SQLException e){
              System.out.println(e);
        }
    }


   

    public void updateCookie(String userName, String cookie, ByteString hash) throws Exception{
        System.out.println(userName);
        System.out.println(cookie);

        if(!hasPublicKey){
            serverPublicKey = getPublicKey("rsaPublicKey");
            hasPublicKey = true;
        }

        verifyUsersTableStateDB();
        
        String query = "UPDATE users SET cookie=?, hash=? WHERE username=?";
                
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, cookie);
            st.setBytes(2, hash.toByteArray());
            st.setString(3, userName);
        
            st.executeUpdate();
            st.close();
        }
        catch(SQLException e){
              System.out.println("Couldn't update cookie" + e);
        }
    }

    public void updateFile(String fileName, ByteString fileContent, ByteString hash) throws Exception{

        verifyFilesTableStateDB();
        
        String query = "UPDATE files SET filecontent=?, hash=? WHERE filename=?"; 

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setBytes(1, fileContent.toByteArray());
            st.setBytes(2, hash.toByteArray());
            st.setString(3, fileName);
        
            st.executeUpdate();
            st.close();

            return;
        } 
        catch(SQLException e){
            System.out.println("Couldn't update fileContent" + e);
        }
    }


    public void deleteFile(String fileName) throws Exception{
        System.out.println(fileName);

        verifyFilesTableStateDB();
        verifyPermissionsTableStateDB();

        String query = "DELETE FROM files WHERE filename=?";
                        
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
        
            st.executeUpdate();
            System.out.println("The file " + fileName + " was deleted.");
            st.close();
        } 
        catch(SQLException e){
            System.out.println(e);
        }

        //apagar permissoes associadas a este ficheiro
        query = "DELETE FROM permissions WHERE filename=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
            System.out.println("deleting this files permissions" + e);
        }
    }


    public void deleteUser(String userName) throws Exception{
        System.out.println("DELETE USER NO BACKUP SERVER");
        System.out.println(userName);
        //FIX (update) parece que nao consegue fazer upload de ficheiros grandes

        verifyUsersTableStateDB();
        verifyFilesTableStateDB();
        verifyPermissionsTableStateDB();
            
        String query = "SELECT filename FROM files WHERE fileowner=?";
    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            ResultSet rs = st.executeQuery();        

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
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } catch(SQLException e){
                System.out.println("deleting this users permissions" + e);
        }

        //apagar ficheiros deste user
        query = "DELETE FROM files WHERE fileowner=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } catch(SQLException e){
                System.out.println("deleting files belonging to deleted user" + e);
        }

        //Delete user
        query = "DELETE FROM users WHERE username=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } catch(SQLException e){
            System.out.println("deleting user " + e);
        }
    }

    public void writeUser(String userName, String hashPassword, ByteString salt, ByteString publicKey, ByteString hash) throws Exception{
        System.out.println(userName);
        System.out.println(hashPassword);
        System.out.println(salt.toStringUtf8());

        if(!hasPublicKey){
            serverPublicKey = getPublicKey("rsaPublicKey");
            hasPublicKey = true;
        }

        verifyUsersTableStateDB();
        
        String query = "INSERT INTO users ("
        + " username,"
        + " password, "
        + " salt, "
        + " publickey, "
        + " hash ) VALUES ("
        + "?, ?, ?, ?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, userName);
            st.setString(2, hashPassword);
            st.setBytes(3, salt.toByteArray());
            st.setBytes(4, publicKey.toByteArray());
            st.setBytes(5, hash.toByteArray());

            st.executeUpdate();
            st.close();
          } catch(SQLException e){
              System.out.println(e);
          } 
    }

    public void writePermission(String fileName, String userName, ByteString symmetricKey, ByteString initializationVector, ByteString hash) throws Exception{
        System.out.println(userName);
        System.out.println(fileName);


        verifyPermissionsTableStateDB();

        String query = "INSERT INTO permissions ("
        + " filename,"
        + " username,"
        + " symmetrickey,"
        + " initializationvector,"
        + " hash ) VALUES ("
        + "?, ?, ?, ?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
            st.setString(2, userName);
            st.setBytes(3, symmetricKey.toByteArray());
            st.setBytes(4, initializationVector.toByteArray());
            st.setBytes(5, hash.toByteArray());

            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
                System.out.println(e);

        }
    }

    public void removePermission(String fileName, String userName) throws Exception{

        verifyPermissionsTableStateDB();
        
        String query = "DELETE FROM permissions WHERE filename=? AND username=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
            st.setString(2, userName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
                System.out.println(e);

        }
    }
}
