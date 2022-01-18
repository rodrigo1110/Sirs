package pt.tecnico.grpc.server.exceptions;

public class UserDoesNotExistException extends Exception{
    
    public UserDoesNotExistException(){
        super("That username does not exist.");
    }
}