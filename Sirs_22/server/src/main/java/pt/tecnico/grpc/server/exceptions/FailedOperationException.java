package pt.tecnico.grpc.server.exceptions;

public class FailedOperationException extends Exception{

    public FailedOperationException(){
        super("Something went wrong with your operation. Please try again.");
    }
}