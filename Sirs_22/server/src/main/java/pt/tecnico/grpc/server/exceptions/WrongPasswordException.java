package pt.tecnico.grpc.server.exceptions;

public class WrongPasswordException extends Exception{

    public WrongPasswordException(){
        super("Wrong password.");
    }
}
