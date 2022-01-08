package pt.tecnico.grpc.server.exceptions;

public class NotSharedWithUserException extends Exception{
    
    public NotSharedWithUserException(){
        super("O seguinte utilizador não faz parte da lista dos utilizadores com acesso ao ficheiro: ");
    }
}
