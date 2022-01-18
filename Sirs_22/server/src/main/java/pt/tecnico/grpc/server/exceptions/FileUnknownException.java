package pt.tecnico.grpc.server.exceptions;

public class FileUnknownException extends Exception {
    
    public FileUnknownException(String fileName){
        super("File " + fileName + " unknown.");
    }
}
