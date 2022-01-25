package pt.tecnico.grpc.server.exceptions;

public class EncryptedSymmetricKeyNotFoundException extends Exception{
    
    public EncryptedSymmetricKeyNotFoundException(){
        super("Encrypted Symmetric Key not found.");
    }
}
