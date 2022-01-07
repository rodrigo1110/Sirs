package pt.tecnico.grpc.server;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.server.databaseAccess;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;

enum ErrorMessage{
	USER_UNKNOWN, FILE_UNKNOWN, EXISTENT_USERNAME, RANSOMWARE_DETECTED, INVALID_COOKIE,
    WRONG_PASSWORD, NO_PERMISSION, NOT_SHARED_WITH_USER, USER_ALREADY_HAS_ACCESS    //Add more later
}

public class mainServer {
    
    //--------------------------user-mainServer implementation--------------------------
    
    public static String errorMessageToString(ErrorMessage errorMessage){
        if(errorMessage == ErrorMessage.USER_UNKNOWN ) 
			return "Utilizador desconhecido.";
		
		else if(errorMessage == ErrorMessage.FILE_UNKNOWN) 
			return "Ficheiro desconhecido.";

		else if(errorMessage == ErrorMessage.EXISTENT_USERNAME) 
			return "O nome de utilizador fornecido já existe.";

		else if(errorMessage == ErrorMessage.INVALID_COOKIE)
			return "Cookie inválida.";
		
		else if(errorMessage == ErrorMessage.WRONG_PASSWORD) 
			return "Password errada.";
		
		else if(errorMessage == ErrorMessage.NO_PERMISSION) 
			return "Sem permissão.";

        else if(errorMessage == ErrorMessage.RANSOMWARE_DETECTED) 
			return "Ataque de ransomware detetado.";

        else if(errorMessage == ErrorMessage.NOT_SHARED_WITH_USER) 
			return "O seguinte utilizador não faz parte da lista dos utilizadores com acesso ao ficheiro: ";
        
        else if(errorMessage == ErrorMessage.USER_ALREADY_HAS_ACCESS) 
			return "O seguinte utilizador já tem acesso: ";

		else 
			return "";	
    }
    
    public String greet(String name){
        return "Hello my dear " + name + "!";
    }

    
    public void signUp(String username, String password) throws Exception{
        //---signup code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.EXISTENT_USERNAME)); 
    }


    public String login(String username, String password) throws Exception{
        //---login code later---
        if(true)
            return "Cookie :-9";
        else
            throw new Exception(errorMessageToString(ErrorMessage.WRONG_PASSWORD)); 
    }


    public void logout(String cookie) throws Exception{
        //---logout code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.INVALID_COOKIE)); 
    }


    public void upload(String fileID, String cookie, ByteString file) throws Exception{
        //---upload code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.INVALID_COOKIE)); 
    }


    public ByteString download(String fileID, String cookie) throws Exception{
        //---download code later---
        if(true)
            return ByteString.copyFromUtf8("Future conversion will be from file to bytestring");
        else
            throw new Exception(errorMessageToString(ErrorMessage.FILE_UNKNOWN)); 
    }


    public void share(String fileID, String cookie, List<String> users) throws Exception{
        //---share code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.USER_ALREADY_HAS_ACCESS)); 
    }


    public void unshare(String fileID, String cookie, List<String> users) throws Exception{
        //---unshare code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.NOT_SHARED_WITH_USER)); 
    }


    public void deleteUser(String username, String password) throws Exception{
        //---delete user code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.USER_UNKNOWN)); 
    }


    public void deleteFile(String fileID, String cookie) throws Exception{
        //---delete file code later---
        if(true) return;
        else
            throw new Exception(errorMessageToString(ErrorMessage.USER_UNKNOWN)); 
    }

}
