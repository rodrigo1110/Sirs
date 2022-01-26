package pt.tecnico.grpc.server.exceptions;

public class DuplicateFileException extends Exception {
    
    public DuplicateFileException(String fileName){
        super("File " + fileName + " already exists. Please, chose another name for your file.");
    }
}
