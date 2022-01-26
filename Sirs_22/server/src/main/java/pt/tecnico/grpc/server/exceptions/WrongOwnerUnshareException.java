package pt.tecnico.grpc.server.exceptions;

public class WrongOwnerUnshareException extends Exception{

    public WrongOwnerUnshareException(){
        super("You are not the owner of this file. You can not unshare it.");
    }
}
