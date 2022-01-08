package pt.tecnico.grpc.server.exceptions;

public class NoPermissionException extends Exception{
    
    public NoPermissionException(){
        super("Sem permissão.");
    }
}
