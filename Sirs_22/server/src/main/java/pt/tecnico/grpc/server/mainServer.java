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

import com.google.protobuf.ByteString;


public class mainServer {
    
    //--------------------------user-mainServer implementation--------------------------
    ManagedChannel channel;
    MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub stub;
    boolean clientActive = false;


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
        //---signup code later---
        if(true) return;
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
        //---share code later---
        if(true) return;
        else
            throw new UserAlreadyHasAccessException(); 
    }


    public void unshare(String fileID, String cookie, List<String> users) throws Exception{
        //---unshare code later---
        if(true) return;
        else
            throw new NotSharedWithUserException(); 
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
