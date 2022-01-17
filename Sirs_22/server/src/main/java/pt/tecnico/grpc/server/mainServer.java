package pt.tecnico.grpc.server;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.server.exceptions.*;
import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.MainBackupServer;

import io.grpc.ManagedChannel;

import java.io.File;
import java.io.InvalidClassException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import java.io.*;


import java.sql.*;

import com.google.protobuf.ByteString;


public class mainServer {
    
    //--------------------------user-mainServer implementation--------------------------
    ManagedChannel channel;
    MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub stub;
    boolean clientActive = false;
    private databaseAccess database = new databaseAccess();
    Connection connection = database.connect();
    private String userName;
    private String password;


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

    
    public void signUp(String username, String password) throws Exception{
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

                    this.userName = username;
                    this.password = password;

                    query = "INSERT INTO users ("
                    + " username,"
                    + " password ) VALUES ("
                    + "?, ?)";
        
                    try {
                        st = connection.prepareStatement(query);
                        st.setString(1, username);
                        st.setString(2, password);
                    
                        st.executeUpdate();
                        st.close();
                      } catch(SQLException e){
                          System.out.println("!!!!!!" + e);
                          throw new ExistentUsernameException();
                      }
                }
            } catch(SQLException e){
                System.out.println(e);
            }         
        }
    }


    public String login(String username, String password) throws Exception{
        /* talvez verificar se user existe */
        String dbPassword = "";

        System.out.println("User " + username + " has attempted to login with password " + password + ".");

        if(checkInput(username, password)){

            String query = "SELECT password FROM users WHERE username=?";

            try {
                PreparedStatement st = connection.prepareStatement(query);
                st.setString(1, username);
            
                ResultSet rs = st.executeQuery();        

                while (rs.next()) {                       
                    dbPassword = rs.getString(1);        
                    
                    System.out.println("Password from database = " + dbPassword);
                    System.out.println("Password from user = " + password);
                    System.out.println("passwords iguais: " + dbPassword.compareTo(password));

                }
                //Integer equals = dbPassword.compareTo(password); // 0 se sao iguais
                if((dbPassword.compareTo(password)) != 0){
                    throw new RansomwareAttackException();
                }
                else{
                    System.out.println("User " + username + " logged in with password " + password + ".");
                    this.userName = username;
                    this.password = password;
                }

/*                 st.close();                       
                rs.close(); */

                } catch(SQLException e){
                    System.out.println(e);
                }

            return "Cookie?";
        }
        else
            throw new RansomwareAttackException();
    }

    public boolean checkInput(String userName, String password){
        return userName.length() <= 45 && userName.length() > 0 && password.length() <= 45 && password.length() > 0;
    }

    public void logout(String cookie) throws Exception{
        //---logout code later---
        if(true) return;
        else
            throw new InvalidCookieException(); 
    }


    public void upload(String fileID, String cookie, ByteString file) throws Exception{
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

        String query = "INSERT INTO files ("
        + " filename,"
        + " filecontent,"
        + " fileowner ) VALUES ("
        + "?, ?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileID);
            st.setBytes(2, file.toByteArray());
            st.setString(3, userName);

        
            st.executeUpdate();
            st.close();
          } catch(SQLException e){
              System.out.println(e);
          }

    }


    public ByteString download(String fileID, String cookie) throws Exception{
        /* falta verificacao de autorizacoes */
        String query = "SELECT filecontent FROM files WHERE filename=?";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileID);
        
            ResultSet rs = st.executeQuery();        

            if (rs.next()) {      

                ByteString bytestring = ByteString.copyFrom(rs.getBytes(1));
                System.out.println("File content = " + bytestring.toStringUtf8());

                return bytestring;
            }
            else{
                throw new FileUnknownException();
            }

        } catch(SQLException e){
                System.out.println(e);
        }
        return ByteString.copyFromUtf8("ERRO");
    }


    public void share(String fileID, String cookie, String user) throws Exception{
        /* Fazer: acrescentar useralreadyhasaccessexception + avisar user se um username estiver errado*/
        String query = "INSERT INTO permissions ("
        + " filename,"
        + " username ) VALUES ("
        + "?, ?)";

        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, fileID);
            st.setString(2, user);
        
            st.executeUpdate();
            st.close();
            } catch(SQLException e){
                System.out.println("?????" + e);

            }
    }


    public void unshare(String fileID, String cookie, List<String> users) throws Exception{
/* 
        //---unshare code later---
        if(true) return;
        else
            throw new NotSharedWithUserException();  */
    }


    public void deleteUser(String username, String password) throws Exception{

        //---delete user code later---
        if(true) return;
        else
            throw new UserUnknownException(); 
    }


    public void deleteFile(String fileID, String cookie) throws Exception{
        //---delete file code later---
        if(true) return;
        else
            throw new UserUnknownException(); 
    }
}
