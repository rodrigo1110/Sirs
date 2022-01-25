package pt.tecnico.grpc.server.exceptions;

public class EncryptedInitializationVectorNotFoundException extends Exception{
    
    public EncryptedInitializationVectorNotFoundException(){
        super("Encrypted Initialization Vector not found.");
    }
}
