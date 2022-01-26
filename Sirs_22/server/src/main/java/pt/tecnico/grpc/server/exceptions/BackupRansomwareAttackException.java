package pt.tecnico.grpc.server.exceptions;

public class BackupRansomwareAttackException extends Exception{
    
    public BackupRansomwareAttackException(){
        super("Ataque de ransomware detetado no backup.");
    }
}
