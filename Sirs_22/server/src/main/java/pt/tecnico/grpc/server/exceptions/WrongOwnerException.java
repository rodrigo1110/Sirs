package pt.tecnico.grpc.server.exceptions;

public class WrongOwnerException extends Exception{

    public WrongOwnerException(){
        super("You are not the owner of this file. You can not share it.");
    }
}
