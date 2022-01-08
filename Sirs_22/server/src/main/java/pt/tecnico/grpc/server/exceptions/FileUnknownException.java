package pt.tecnico.grpc.server.exceptions;

public class FileUnknownException extends Exception {
    
    public FileUnknownException(){
        super("Ficheiro desconhecido.");
    }
}
