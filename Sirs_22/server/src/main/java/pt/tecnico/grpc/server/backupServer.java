package pt.tecnico.grpc.server;

import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.server.Security;
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

    /*------------------------------------ Database Functionss ------------------------------------------------*/

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
        return Security.hashString(new String(message), new byte[0]);
    }

    public String createFileHashDb(String fileID, byte[] fileContent, String fileOwner) throws Exception{

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileID.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileContent);
        messageBytes.write(":".getBytes());
        messageBytes.write(fileOwner.getBytes());
       
        byte[] message = messageBytes.toByteArray();
        return Security.hashString(new String(message), new byte[0]);
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
        return Security.hashString(new String(message), new byte[0]);
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
                String hashLineDB = Security.decrypt(serverPublicKey, encryptedHashLineDB);
                String hashLine = createUserHashDb(userName, password, cookie, salt, publicKeyDB);
                
                if(hashLineDB.compareTo(hashLine) != 0){ 
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
                
                String hashLineDB = Security.decrypt(serverPublicKey, encryptedHashLineDB);
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
      
                String hashLineDB = Security.decrypt(serverPublicKey, encryptedHashLineDB);
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

    
    /*------------------------------------ MainServer-BackUp Communication------------------------------------------------*/

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
        } 
        catch(SQLException e){
              System.out.println(e);
        }
    }

    public void updateCookie(String userName, String cookie, ByteString hash) throws Exception{

        if(!hasPublicKey){
            serverPublicKey = Security.getPublicKey("rsaPublicKey");
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
              System.out.println(e);
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
            System.out.println(e);
        }
    }

    public void deleteFile(String fileName) throws Exception{

        verifyFilesTableStateDB();
        verifyPermissionsTableStateDB();

        String query = "DELETE FROM files WHERE filename=?";
                        
        try {
            PreparedStatement st = connection.prepareStatement(query);

            st.setString(1, fileName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
            System.out.println(e);
        }

        query = "DELETE FROM permissions WHERE filename=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
            System.out.println(e);
        }
    }

    public void deleteUser(String userName) throws Exception{

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
                
                query = "DELETE FROM permissions WHERE filename=?";
                            
                try {
                    st = connection.prepareStatement(query);
                    st.setString(1, fileName);
                
                    st.executeUpdate();
                    st.close();
                } 
                catch(SQLException e){
                        System.out.println(e);
                }
            }
        }
        catch(Exception e){
            System.out.println(e.toString());
        }

        query = "DELETE FROM permissions WHERE username=?";
            
        try {
            PreparedStatement st = connection.prepareStatement(query);

            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
                System.out.println(e);
        }

        query = "DELETE FROM files WHERE fileowner=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);

            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
                System.out.println(e);
        }

        query = "DELETE FROM users WHERE username=?";
                    
        try {
            PreparedStatement st = connection.prepareStatement(query);

            st.setString(1, userName);
        
            st.executeUpdate();
            st.close();
        } 
        catch(SQLException e){
            System.out.println(e);
        }
    }

    public void writeUser(String userName, String hashPassword, ByteString salt, ByteString publicKey, ByteString hash) throws Exception{

        if(!hasPublicKey){
            serverPublicKey = Security.getPublicKey("rsaPublicKey");
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
        } 
        catch(SQLException e){
            System.out.println(e);
        } 
    }

    public void writePermission(String fileName, String userName, ByteString symmetricKey, ByteString initializationVector, ByteString hash) throws Exception{

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
