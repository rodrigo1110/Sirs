package pt.tecnico.grpc.server.exceptions;

public class UserUnknownException extends Exception{

    public UserUnknownException(){
        super("Utilizador desconhecido.");
    }
}