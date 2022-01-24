package pt.tecnico.grpc.server.exceptions;

public class MessageIntegrityException extends Exception {
    
    public MessageIntegrityException(){
        super("Message integrity compromised.");
    }
}
