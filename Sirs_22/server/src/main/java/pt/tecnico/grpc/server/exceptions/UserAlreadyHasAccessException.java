package pt.tecnico.grpc.server.exceptions;

public class UserAlreadyHasAccessException extends Exception {
    public UserAlreadyHasAccessException(){
        super("O seguinte utilizador já tem acesso: ");
    }
}
