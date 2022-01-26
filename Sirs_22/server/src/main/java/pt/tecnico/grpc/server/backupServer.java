package pt.tecnico.grpc.server;

import pt.tecnico.grpc.server.databaseAccess;

import java.sql.*;

import javax.lang.model.util.ElementScanner6;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;

import com.google.protobuf.ByteString;


public class backupServer {

    private databaseAccess database = new databaseAccess("rdabackup");
    Connection connection = database.connect();
    
    //--------------------------mainServer-backupServer implementation--------------------------
    
    //----------------------TO DO: add correct exceptions later------------------------

    public String greet(String name){
        return "Hello " + name + ". I am instance number ";
    }



    public void promote() throws Exception{
        //---promote code later---
        if(true) return;//if everything is fine (no ransomware attack on this backup) and ready for promotion
        else
            throw new Exception();
    }

    
    


    public void writeFile(String fileName, ByteString fileContent, String fileOwner, ByteString hash) throws Exception{

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


   

    public void updateCookie(String userName, String cookie, ByteString hash){
        System.out.println(userName);
        System.out.println(cookie);

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

    public void updateFile(String fileName, ByteString fileContent, ByteString hash){

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

    public void deleteFile(String fileName){
        System.out.println(fileName);

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

    public void deleteUser(String userName){
        System.out.println("DELETE USER NO BACKUP SERVER");
        System.out.println(userName);
        //apagar permissoes dos ficheiros deste user
            
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
    }

    public void writeUser(String userName, String hashPassword, ByteString salt, ByteString publicKey, ByteString hash){
        System.out.println(userName);
        System.out.println(hashPassword);
        System.out.println(salt.toStringUtf8());

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
