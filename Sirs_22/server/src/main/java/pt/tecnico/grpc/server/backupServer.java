package pt.tecnico.grpc.server;

import pt.tecnico.grpc.server.databaseAccess;

import javax.lang.model.util.ElementScanner6;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;

import com.google.protobuf.ByteString;


public class backupServer {
    
    //--------------------------mainServer-backupServer implementation--------------------------
    
    //----------------------TO DO: add correct exceptions later------------------------

    public String greet(String name){
        return "Hello " + name + ". I am instance number ";
    }


    public MainBackupServer.heartbeatResponse heartbeat(int instance) throws Exception{
        //---heartbeat code in last version of program(multiple backups)---
        if(true)
            return MainBackupServer.heartbeatResponse.newBuilder()
            .setInstance(instance).setStatus("Ok").setSequenceOverview(1000).build();
        else
            throw new Exception();
    }


    public void promote() throws Exception{
        //---promote code later---
        if(true) return;//if everything is fine (no ransomware attack on this backup) and ready for promotion
        else
            throw new Exception();
    }

    
    public void write(String username, String field, String value, int sequence) throws Exception{
        //---write code later---
        if(true) return;
        else
        throw new Exception();
    }


    public void writeFile(String username, String fileID, ByteString file, int sequence) throws Exception{
        //---writeFile code later---
        if(true) return;
        else
        throw new Exception();
    }


    public MainBackupServer.readResponse read(String username, String field) throws Exception{
        //---read code later---
        if(true)
            return MainBackupServer.readResponse.newBuilder()
            .setValue("ROOT").setSequence(1000).build();
        else
            throw new Exception();
    }


    public MainBackupServer.readFileResponse readFile(String username, String fileID) throws Exception{
        //---readFile code later---
        if(true)
            return MainBackupServer.readFileResponse.newBuilder()
            .setFileContent(ByteString.copyFromUtf8("Future conversion will be from file to bytestring")).setSequence(1000).build();
        else
            throw new Exception();
    }  
}
