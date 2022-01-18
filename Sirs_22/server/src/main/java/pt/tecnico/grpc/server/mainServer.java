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
    
    
    public String hashString(){
        return ("ola");
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

    public String createCookie(String userName, String password){
        String cookie = userName + password;
        return cookie;
    }

    public String login(String username, String password) throws Exception{
        

        String dbPassword = "";

        System.out.println("User " + username + " has attempted to login with password " + password + ".");

        if(checkInput(username, password)){

            //check if user is registered
            String query = "SELECT username FROM users WHERE username=?";
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
                        //Integer equals = dbPassword.compareTo(password); // 0 se sao iguais
                        if((dbPassword.compareTo(password)) != 0){
                            throw new WrongPasswordException();
                        }
                        else{
                            System.out.println("User " + username + " logged in with password " + password + ".");
                            this.userName = username;
                            this.password = password;
                                                        
                            //creates cookie and adds it to database
                            String cookie = createCookie(username, password);

                            //criar/atualizar cookie na base de dados
                            query = "UPDATE users SET cookie=? WHERE username=?";
                
                            try {
                                st = connection.prepareStatement(query);
                                st.setString(1, cookie);
                                st.setString(2, username);
                            
                                st.executeUpdate();
                                st.close();
                              } catch(SQLException e){
                                  System.out.println("Couldn't update cookie" + e);
                              }

                            return cookie;
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
            return "Cookie?";
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
                
                System.out.println("O dono do fichero e " + dbUserName);

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
    }

    public String correspondentUser(String cookie){

        String dbUserName = "";
        String query = "SELECT username FROM users WHERE cookie=?";


        try {
            PreparedStatement st = connection.prepareStatement(query);
            st.setString(1, cookie);
        
            ResultSet rs = st.executeQuery();        

            if (rs.next()) {      
                dbUserName = rs.getString("username");
                System.out.println("Username: " + dbUserName);
                return dbUserName;

            }
        } catch(SQLException e){
                System.out.println(e);
        }
        System.out.println("Username fora do try e if: " + dbUserName);

        return dbUserName;
    }

    public ByteString download(String fileID, String cookie) throws Exception{

        //encontrar username correspondente a cookie recebida

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
    
                    return bytestring;
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
        return ByteString.copyFromUtf8("ERRO");
    }


    public void share(String fileID, String cookie, List<String> user) throws Exception{ //se um dos nomes inseridos pelo user estiver errado, mais nenhum e adicionado, por causa da excecao.
        //check if the file exists - done
        //check if "I" am the owner of the file - done, need to update after cookie done
        //check if user already had permission - done
        for (String userName : user) {
            if(checkIfFileExists(fileID)){
                if(checkIfUserExists(userName)){
                    if(checkFileOwner(fileID, this.userName)){ //este userName depois vem na cookie
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
            throw new UserUnknownException(username); 
    }


    public void deleteFile(String fileID, String cookie) throws Exception{
        //---delete file code later---
        if(true) return;
        else
            throw new UserUnknownException(fileID); 
    }
}
