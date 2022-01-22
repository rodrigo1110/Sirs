package pt.tecnico.grpc.server.exceptions;

public class NotSharedWithUserException extends Exception{
    
    public NotSharedWithUserException(){
        super("You don't have permission to download that file.");
    }
}
