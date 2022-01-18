package pt.tecnico.grpc.server.exceptions;

public class UserUnknownException extends Exception{

    public UserUnknownException(String userName){
        super("User " + userName + " unknown.");
    }
}