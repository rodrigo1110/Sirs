package pt.tecnico.grpc.server.exceptions;

public class TimestampException extends Exception{
    
    public TimestampException(){
        super("Operation time expired.");
    }
}
