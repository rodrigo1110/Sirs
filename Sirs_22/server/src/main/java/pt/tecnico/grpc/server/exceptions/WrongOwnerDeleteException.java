package pt.tecnico.grpc.server.exceptions;

public class WrongOwnerDeleteException extends Exception{

    public WrongOwnerDeleteException(){
        super("You are not the owner of this file. You can not delete it.");
    }
}
