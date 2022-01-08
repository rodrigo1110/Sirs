package pt.tecnico.grpc.server.exceptions;

public class RansomwareAttackException extends Exception{
    
    public RansomwareAttackException(){
        super("Ataque de ransomware detetado.");
    }
}
