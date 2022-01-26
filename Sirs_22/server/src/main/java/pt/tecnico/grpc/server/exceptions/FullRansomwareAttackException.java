package pt.tecnico.grpc.server.exceptions;

public class FullRansomwareAttackException extends Exception {
   
    public FullRansomwareAttackException(){
        super("Ransomware attack detected in the whole system. Shutting down...");
    }
}
