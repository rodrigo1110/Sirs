package pt.tecnico.grpc.server.exceptions;

public class UserAlreadyHasAccessException extends Exception {
    public UserAlreadyHasAccessException(String userName){
        super("The user " + userName + " already has access to the file.");
    }
}
