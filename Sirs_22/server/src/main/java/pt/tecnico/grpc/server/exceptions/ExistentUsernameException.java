package pt.tecnico.grpc.server.exceptions;

public class ExistentUsernameException extends Exception{
    
    public ExistentUsernameException(){
        super("O nome de utilizador fornecido já existe.");
    }
}
