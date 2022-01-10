package pt.tecnico.grpc.server;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.server.exceptions.*;
import pt.tecnico.grpc.server.databaseAccess;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.MainBackupServer;

import io.grpc.ManagedChannel;

import java.io.File;
import java.io.InvalidClassException;
import java.util.ArrayList;
import java.util.List;

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

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("select * from users where username=" + username);
        if(!rs.next()){
            System.out.println("Creating new user account. Adding it to the database.\n");
            rs = stmt.executeQuery("insert into users(username, password) values(" + username + "," + password + ")");
            while (rs.next()) {
				String userName = rs.getString("username");
				System.out.println(userName + " now has an account.\n");
			} 
        }
        else
            throw new ExistentUsernameException(); 
    }


    public String login(String username, String password) throws Exception{
        //---login code later---
        if(1==2)
            return "Cookie :-9";
        else
            throw new RansomwareAttackException();
    }


    public void logout(String cookie) throws Exception{
        //---logout code later---
        if(true) return;
        else
            throw new InvalidCookieException(); 
    }


    public void upload(String fileID, String cookie, ByteString file) throws Exception{
        //---upload code later---
        if(true) return;
        else
            throw new InvalidCookieException(); 
    }


    public ByteString download(String fileID, String cookie) throws Exception{
        //---download code later---
        if(true)
            return ByteString.copyFromUtf8("Future conversion will be from file to bytestring");
        else
            throw new FileUnknownException(); 
    }


    public void share(String fileID, String cookie, List<String> users) throws Exception{

/*         Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("select * from users where username=" + username);
        if(rs.next()){
            Syste.ou.println("Sharing " + fileID + " with the following users: " + users.toString() + "\n");
            ResultSet rs = stmt.executeQuery("insert into files(filename, allowedusers, owner) values(" + fileID + "," + allowedusers + "," + owner + ")");
            while (rs.next()) {
				String userName = rs.getString("username");
				System.out.println(userName + " now has an account.\n");
			} 
        }
        else
            throw new ExistentUsernameException(); 

        //---share code later---
        if(true) return;
        else
            throw new UserAlreadyHasAccessException();  */
    }


    public void unshare(String fileID, String cookie, List<String> users) throws Exception{
/* 
        String owner;

        ResultSet rs = stmt.executeQuery("select owner from files where filename=" + fileID);

        owner = rs.getString("owner");

        ResultSet rs = stmt.executeQuery("select allowedusers from files where filename=" + fileID);

        ResultSet rs = stmt.executeQuery("delete from files where filename=" + fileID);

        ResultSet rs = stmt.executeQuery("insert into files(filename, allowedusers, owner) values(" + fileID + "," + allowedusers + "," + owner + ")");

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
