package pt.tecnico.grpc.server.exceptions;

public class InvalidCookieException extends Exception {
    
    public InvalidCookieException(){
        super("Cookie inválida.");
    }
}
