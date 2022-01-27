package pt.tecnico.grpc.user;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;
import pt.tecnico.grpc.user.Security;


import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.sql.Timestamp;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.net.ssl.SSLException;

import com.google.protobuf.ByteString;

import java.security.*;
import java.security.spec.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.io.DataOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;



public class UserImpl {

    private String host;
	private int port;
    private String cookie = "";
    ManagedChannel channel;
    UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub;
    private static Key privateKey;
    private static Key publicKey;
    private static Key serverPublicKey;
    private static boolean hasServerPublicKey = false;
    private String username = "";
    private String target;


    public UserImpl(String Host, int Port){
        target = Host + ":" + Port;
        new File("publicKey").mkdirs();
        new File("privateKey").mkdirs();
        new File("files").mkdirs();
	}

    public void setTarget(String Host, int Port){
        target = Host + ":" + Port;
    }

    public String getCookie(){
        return cookie;
    }

    public void hello() throws Exception{
        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);
        UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
		UserMainServer.HelloRequest request = UserMainServer.HelloRequest.newBuilder().setName("friend").build();

		UserMainServer.HelloResponse response = stub.greeting(request);
		System.out.println(response);
    }


    public void signup() throws Exception{
		
        System.out.println("------------------------------");
        System.out.println("User Registration");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        while((userName.compareTo("x")) == 0){
            System.out.println("You can't use that username. Please, chose another one.");
            System.out.print("Username: ");
            userName = System.console().readLine();
        }
       
        String password = Security.safePassword();

        //---------------------------------------------------------------------------------------
        try{
            Security.createKeys(userName);
            
        }catch(NoSuchAlgorithmException e) {
            System.out.println("No algorithm");
        }catch(Exception e){
            throw new RuntimeException(e);
        }
        
        if(!hasServerPublicKey){
            serverPublicKey = Security.getPublicKey("../server/rsaPublicKey");
            hasServerPublicKey = true;
        }



        String targetPublic = "publicKey/" + userName + "-PublicKey";
        String targetPrivate = "privateKey/" + userName + "-PrivateKey";
        publicKey = Security.getPublicKey(targetPublic);
        privateKey = Security.getPrivateKey(targetPrivate);
        
        ByteString encryptedPassword = ByteString.copyFrom(Security.encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        String path = "publicKey/" + userName + "-PublicKey";
        byte[] clientPublicKeyBytes = Files.readAllBytes(Paths.get(path));
        ByteString encryptedPublicKey = ByteString.copyFrom(Security.encryptKey(clientPublicKeyBytes, serverPublicKey));
        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPublicKey.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());
        
        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));


        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);

        UserMainServer.signUpRequest request = UserMainServer.signUpRequest.newBuilder()
            .setUserName(userName).setPassword(encryptedPassword).setPublicKeyClient(encryptedPublicKey)
            .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        stub.signUp(request);
        
        System.out.println("Successful Registration! Welcome " + userName + ".");
    }    
    


    public void login() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        username = userName;
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        StringBuilder sb = new StringBuilder("");
        System.out.print("Please, enter your password: ");
		char [] input = System.console().readPassword();
        sb.append(input);
        String password = sb.toString();
        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("-------- ----------------------");

        

        if(!hasServerPublicKey){
            serverPublicKey = Security.getPublicKey("../server/rsaPublicKey");
            hasServerPublicKey = true;
        }
        try{
            String targetPublic = "publicKey/" + userName + "-PublicKey";
            String targetPrivate = "privateKey/" + userName + "-PrivateKey";
            publicKey = Security.getPublicKey(targetPublic);
            privateKey = Security.getPrivateKey(targetPrivate);
        }catch(NoSuchFileException e){
            System.out.println("User not existent locally. Must sign up locally first.");
            return;
        }

        ByteString encryptedPassword = ByteString.copyFrom(Security.encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));

        File tls_cert = new File("../server/tlscert/server.crt");
        channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
    
        stub = UserMainServerServiceGrpc.newBlockingStub(channel);

        UserMainServer.loginRequest request = UserMainServer.loginRequest.newBuilder().
        setUserName(userName).setPassword(encryptedPassword)
        .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        UserMainServer.loginResponse response = stub.login(request);

        byte[] cookie = response.getCookie().toByteArray();
        String cookieDecrypted = Security.decrypt(privateKey, cookie);
        byte[] hashCookie = response.getHashCookie().toByteArray();
        String hashCookieDecrypted = Security.decrypt(serverPublicKey, hashCookie);

        if(!(Security.verifyMessageHash(cookieDecrypted.getBytes(), hashCookieDecrypted))){
            System.out.println("Response message corrupted.");
            return;
        }

        this.cookie = cookieDecrypted;
        
        username = userName;

        System.out.println("Successful Login! Welcome back " + userName + ".");
    }



    public void logout() throws Exception{
 		      
        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));


        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));
        
        
        UserMainServer.logoutRequest request = UserMainServer.logoutRequest.
        newBuilder().setCookie(encryptedhashCookie).setTimeStamp(encryptedTimeStamp).
        setHashMessage(encryptedHashMessage).build();

        stub.logout(request);
            
        cookie = "";
        System.out.println("Successful logout.");
    }




    public void share() throws Exception{
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to share: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to share this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username " + counter + ": ");
            counter++;
            userName = System.console().readLine();
            if(!listOfUsers.contains(userName)){
                listOfUsers.add(userName);
            }
        }
        //delete de 'x'
        listOfUsers.remove(listOfUsers.size()-1);

        if(listOfUsers.size() == 0){
            System.out.println("You must insert at least one user to share this file with.");
            return;
        }

        //-------------File Obtained from Uploads Directory
        

        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.shareRequest request = UserMainServer.shareRequest.newBuilder().
            setFileId(fileName).addAllUserName(listOfUsers).setCookie(encryptedhashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        UserMainServer.shareResponse response = stub.share(request);


        //-----------------Verify response and obtain its fields--------------

        //chave simetrica (que encriptou o ficheiro) encriptada com a chave publica do (cada um) cliente que tem acesso ao ficheiro
        //Obter campos shareResponse
        byte[] encryptedSymmetricKeyByteArray = response.getSymmetricKey().toByteArray();
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        List<ByteString> encryptedPublicKeyList = response.getPublicKeysList(); //ENVIAR ISTO ASSIM COMO STRING DO SERVDIOR
        List<String> wrongUserList = response.getWrongUserNameList();
        List<String> wrongUserListPermissions = response.getWrongUserNamePermissionList();


        byte[] SymmetricKeyByteArray = Security.decryptKey(encryptedSymmetricKeyByteArray, privateKey);
        
        List<byte[]> listOfPublicKeys = new ArrayList<byte[]>();
        
        for(int i = 0; i < response.getPublicKeysList().size(); i++){
            listOfPublicKeys.add(Security.decryptKey(response.getPublicKeys(i).toByteArray(), privateKey)); //do lado ddo servidor temos de encriptar cada elemento da lista individualmente
        }

        if(!(Security.verifyTimeStamp(response.getTimeStamp(),serverPublicKey))){
            System.out.println("Response took to long");
            return;
        }


        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());

        for(int i = 0; i < encryptedPublicKeyList.size(); i++ ){
            responseBytes.write(encryptedPublicKeyList.get(i).toByteArray()); //-------This one is different from the one sent by server by a few bits
            responseBytes.write(":".getBytes());
        }
        responseBytes.write(wrongUserList.toString().getBytes());
        responseBytes.write(":".getBytes());
        responseBytes.write(wrongUserListPermissions.toString().getBytes());
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = Security.decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!(Security.verifyMessageHash(responseBytes.toByteArray(), hashResponseString))){
            System.out.println("Response integrity compromised");
        } 

        int removedUsers = 0;

        List<String> listOfUsersToCompare = new ArrayList<>(listOfUsers);
        for (String wrongUserName : wrongUserList) {
            if(listOfUsers.remove(wrongUserName)){
                removedUsers++;
            }
            System.out.println("User " + wrongUserName + " doesn't exist. You can't share the file " + fileName + " with this user.");
        }
        for (String wrongUserName : wrongUserListPermissions) {
            if(listOfUsers.remove(wrongUserName)){
                removedUsers++;
            }
            if(wrongUserName.compareTo(this.username) == 0){
                System.out.println("You can 't share a file with yourself.");
            }
            else{
                System.out.println("User " + wrongUserName + " already has permission to access the file " + fileName + ".");
        
            }
        }

        shareKey(listOfPublicKeys, listOfUsers, SymmetricKeyByteArray, fileName, encryptedhashCookie);

        if(listOfUsersToCompare.size() != removedUsers){
                System.out.println("The file " + fileName + " was successfully shared with: ");
                for (String user : listOfUsersToCompare) {
                    if(!wrongUserList.contains(user) &&  !wrongUserListPermissions.contains(user) && (user.compareTo(this.username)) != 0){
                        System.out.println("- " + user);
                    }
                }
        }
    }

    


    public void shareKey(List<byte[]> listOfPublicKeys, List<String> listOfUsers,
        byte[] symmetricKey, String fileName, ByteString encryptedHashCookie) throws Exception{
        

        List<ByteString> listOfEncryptedSymmetricKeysByteString = new ArrayList<>();

        for(int i = 0; i < listOfPublicKeys.size(); i++){
            X509EncodedKeySpec spec = new X509EncodedKeySpec(listOfPublicKeys.get(i));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            Key userPublicKey = kf.generatePublic(spec);
            listOfEncryptedSymmetricKeysByteString.add(ByteString.copyFrom(Security.encryptKey(symmetricKey, userPublicKey)));
        }

        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        
        for(int i = 0; i < listOfEncryptedSymmetricKeysByteString.size(); i++ ){
            messageBytes.write(listOfEncryptedSymmetricKeysByteString.get(i).toByteArray()); 
            messageBytes.write(":".getBytes());
        }
        
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));
    
        UserMainServer.shareKeyRequest request = UserMainServer.shareKeyRequest.newBuilder().
            setFileId(fileName).addAllSymmetricKey(listOfEncryptedSymmetricKeysByteString).addAllUserNames(listOfUsers).setCookie(encryptedHashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        
        stub.shareKey(request);
    }


    public void unshare() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to unshare: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to unshare this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username " + counter + ": ");
            counter++;
            userName = System.console().readLine();
            listOfUsers.add(userName);
        }
        //delete de 'x'
         listOfUsers.remove(listOfUsers.size()-1);

        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(listOfUsers.toString().getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));
        
        UserMainServer.unshareRequest request = UserMainServer.unshareRequest.newBuilder().setFileId(fileName)
            .addAllUserName(listOfUsers).setCookie(encryptedhashCookie)
            .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
    
        UserMainServer.unshareResponse response = stub.unshare(request);

        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        List<String> wrongUserList = response.getWrongUserNameList();
        
        if(!(Security.verifyTimeStamp(response.getTimeStamp(),serverPublicKey))){
            System.out.println("Response took to long");
            return;
        }

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();

        responseBytes.write(wrongUserList.toString().getBytes());
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = Security.decrypt(serverPublicKey, encryptedhashResponseByteArray);

        if(!(Security.verifyMessageHash(responseBytes.toByteArray(), hashResponseString))){
            System.out.println("Response integrity compromised");
        } 
        for (String wrongUserName : wrongUserList) {
            System.out.println("User " + wrongUserName + " doesn't exist. You can't unshare the file " + fileName + " with this user.");
        }

        if(listOfUsers.size() != wrongUserList.size()){
            System.out.println("The file " + fileName + " was successfully unshared with: ");
            for (String user : listOfUsers) {
                if(!wrongUserList.contains(user)){
                    System.out.println("- " + user);
                }
            }
        }
    }
    



    public void downloadLocally(String fileName, byte[] decryptedFileContentByteArray) throws Exception{
        File file = null;
        file = new File("files/" + fileName);

        if (file.createNewFile()) {
            System.out.println("New file created: " + file.getName());
            OutputStream os = new FileOutputStream(file);
            os.write(decryptedFileContentByteArray);
            os.close();
            System.out.println("Successful Download! You can find your downloaded file in your files directory.");
        } 
        else {
            System.out.println("A file with the same name already exists in your files directory. Are you sure you want to replace it? (Y/n)");
            System.out.print("> ");
            String replace = System.console().readLine();
            
            if(replace.compareTo("Y") == 0){
                if (file.delete()) {
                    System.out.println("File replaced successfully");
                    OutputStream os = new FileOutputStream(file);
                    os.write(decryptedFileContentByteArray);
                    os.close();
                    System.out.println("Successful Download! You can find your downloaded file in your files directory.");
                }
                else 
                    System.out.println("Failed to delete the file");
            }
            else
                System.out.println("File was not replaced.");
        }
    }

    public void createFile() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to create: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");

        File file = null;
        file = new File("files/" + fileName);

        if (file.createNewFile()) {
            System.out.println("File " + file.getName() + " created.");
        } 
        else {
            System.out.println("A file with the same name already exists in your files directory. Are you sure you want to replace it? (Y/n)");
            System.out.print("> ");
            String replace = System.console().readLine();
            
            if(replace.compareTo("Y") == 0){
                if (file.delete()) {
                    System.out.println("File replaced successfully");
                }
                else 
                    System.out.println("Failed to delete the file");
            }
            else
                System.out.println("File was not replaced.");
        }
    }

    public void editFile() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to edit: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");

        File file = null;
        file = new File("files/" + fileName);

        if(file.createNewFile()) {
            System.out.println("File " + file.getName() + " created.");
            OutputStream os = new FileOutputStream(file);

            System.out.println("------------------------------");
            System.out.println("Please, enter the new file content. When you are done, press Enter.");

            String fileContent = System.console().readLine();

            //while(!fileContent.equals("x")){
                os.write(fileContent.getBytes());
            //}

            os.close();
            System.out.println("Successful edit!");
        } 
        else {            
                if(file.delete()) {

                    System.out.println("------------------------------");
                    System.out.println("Please, enter the new file content. When you are done, press Enter.");
                    String fileContent = System.console().readLine();

                    OutputStream os = new FileOutputStream(file);

                    //while(!fileContent.equals("x")){
                        os.write(fileContent.getBytes());
                    //}

                    os.close();
                    System.out.println("Successful edit!");

                }
                else 
                    System.out.println("Failed to delete the file");
        }
    }

    

    public void download() throws Exception{
		
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to download: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        
        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));


        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.downloadRequest request = UserMainServer.downloadRequest.newBuilder().
            setFileId(fileName).setCookie(encryptedhashCookie).
            setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();

        UserMainServer.downloadResponse response = stub.download(request);


        byte[] encryptedFileContentByteArray = response.getFileContent().toByteArray();
        byte[] encryptedSymmetricKeyByteArray = response.getKey().toByteArray();
        byte[] initializationVectorByteArray = response.getInitializationVector().toByteArray();
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        
        if(!(Security.verifyTimeStamp(response.getTimeStamp(),serverPublicKey))){
            System.out.println("Response took to long");
            return;
        }

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(encryptedFileContentByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(initializationVectorByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = Security.decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!(Security.verifyMessageHash(responseBytes.toByteArray(), hashResponseString))){
            System.out.println("Response integrity compromised");
            return;
        }

        byte[] decryptedSymmetricKeyByteArray = Security.decryptKey(encryptedSymmetricKeyByteArray, privateKey);
        SecretKey decryptedSymmetricKey = new SecretKeySpec(decryptedSymmetricKeyByteArray, 0, decryptedSymmetricKeyByteArray.length, "AES");

        byte[] decryptedFileContentByteArray = Security.decryptAES(encryptedFileContentByteArray, decryptedSymmetricKey, initializationVectorByteArray);

        downloadLocally(fileName,decryptedFileContentByteArray);
    }


    public UserMainServer.isUpdateResponse isUpdate(String fileName, ByteString encryptedHashCookie) throws Exception{
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));


        UserMainServer.isUpdateRequest request = UserMainServer.isUpdateRequest.newBuilder().
                setFileId(fileName).setTimeStamp(encryptedTimeStamp).setCookie(encryptedHashCookie).
                setHashMessage(encryptedHashMessage).build();
        UserMainServer.isUpdateResponse response = stub.isUpdate(request);

        byte isUpdate = (byte)(response.getIsUpdate()?1:0);
        byte[] encryptedSymmetricKeyByteArray = response.getSymmetricKey().toByteArray();
        byte[] initializationVectorByteArray = response.getInitializationVector().toByteArray();
        byte[] encryptedhashResponseByteArray = response.getHashMessage().toByteArray();
        byte[] encryptedTimeStampByteArray = response.getTimeStamp().toByteArray();
        
        if(!(Security.verifyTimeStamp(response.getTimeStamp(),serverPublicKey))){
            System.out.println("Response took to long.");
            return null;
        }

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        responseBytes.write(isUpdate);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedSymmetricKeyByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(initializationVectorByteArray);
        responseBytes.write(":".getBytes());
        responseBytes.write(encryptedTimeStampByteArray);

        String hashResponseString = Security.decrypt(serverPublicKey, encryptedhashResponseByteArray);
        if(!(Security.verifyMessageHash(responseBytes.toByteArray(), hashResponseString))){
            System.out.println("Response integrity compromised");
            return null;
        }
        return response;
    }

    public void showFiles() throws Exception{

        UserMainServer.showFilesRequest request = UserMainServer.showFilesRequest.newBuilder().
                setUserName(this.username).build();

        UserMainServer.showFilesResponse response = stub.showFiles(request);

        List<String> listOfFiles = response.getFileNameList();

        System.out.println("This are the files you have permission to download: ");

        for(int i = 0; i < listOfFiles.size(); i++){
            System.out.print("- ");
            String fileName = listOfFiles.get(i);
            String[] fileNameToSplit = fileName.split("\\.");
            fileName = fileNameToSplit[0];
            System.out.println(fileName);
        }
    }

    
    public void upload() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to upload: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        byte[] byteArray = new byte[0];
        try{
            Path path = Paths.get("files/" + fileName);
            byteArray = Files.readAllBytes(path);
        }catch (Exception e){
            if(e.getClass().toString().compareTo("class java.nio.file.NoSuchFileException") == 0)
                System.out.println("That file does not exist in your files directory.");
            return;
        }

        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedHashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));

        UserMainServer.isUpdateResponse response = isUpdate(fileName,encryptedHashCookie);

        Key SymmetricKey;
        byte[] symmetricKeyArray;
        byte[] initializationVector;

        if(response == null)
            return;
        if(response.getIsUpdate()){
            symmetricKeyArray = Security.decryptKey(response.getSymmetricKey().toByteArray(), privateKey);
            SymmetricKey = new SecretKeySpec(symmetricKeyArray, 0, symmetricKeyArray.length, "AES");
            initializationVector = response.getInitializationVector().toByteArray();
        }
        else{
            SymmetricKey = Security.createAESKey();
            symmetricKeyArray = SymmetricKey.getEncoded(); //se der erro ---> outra forma
            initializationVector = Security.createInitializationVector();
        }
        byte[] encryptedFileContentBytes = Security.encryptAES(byteArray, SymmetricKey, initializationVector);
        ByteString encryptedFileContentByteString = ByteString.copyFrom(encryptedFileContentBytes);        
        
        ByteString encryptedSymmetricKey = ByteString.copyFrom(Security.encryptKey(symmetricKeyArray, publicKey));
        ByteString initializationVectorByteString = ByteString.copyFrom(initializationVector);
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));
        
        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedHashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedFileContentBytes);
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedSymmetricKey.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(initializationVectorByteString.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));
        
        UserMainServer.uploadRequest request = UserMainServer.uploadRequest.newBuilder().
        setFileId(fileName).setFileContent(encryptedFileContentByteString).
        setSymmetricKey(encryptedSymmetricKey).setInitializationVector(initializationVectorByteString).
        setTimeStamp(encryptedTimeStamp).setCookie(encryptedHashCookie).
        setHashMessage(encryptedHashMessage).build();

        stub.upload(request);

        System.out.println("Successful Upload!");
    }


    public void deleteUser() throws Exception{
            
        System.out.println("------------------------------");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        StringBuilder sb = new StringBuilder("");
        System.out.print("Please, enter your password: ");
		char [] input = System.console().readPassword();
        sb.append(input);
        String password = sb.toString();

        if(userName.compareTo(this.username) != 0){
            System.out.println("That is not your username. Please, try again.");
            return;
        }       
        
        ByteString encryptedPassword = ByteString.copyFrom(Security.encrypt(serverPublicKey, password.getBytes()));
        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(userName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedPassword.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));
        
        
        UserMainServer.deleteUserRequest request = UserMainServer.deleteUserRequest.newBuilder().setUserName(userName)
            .setPassword(encryptedPassword).setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        stub.deleteUser(request);

        File file = new File("publicKey/" + username + "-PublicKey");

        file.delete();

        file = new File("privateKey/" + username + "-PrivateKey");

        file.delete();

        System.out.println("User deleted successfully!");
        cookie = "";
    }


    public void deleteFile() throws Exception{

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to delete: ");
        String fileName = System.console().readLine();
        fileName = fileName.concat(".txt");
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        
        String hashCookie = Security.hashMessage(cookie);
        ByteString encryptedhashCookie = ByteString.copyFrom(Security.encrypt(serverPublicKey, hashCookie.getBytes()));


        ByteString encryptedTimeStamp = ByteString.copyFrom(Security.encrypt(privateKey, Security.getTimeStampBytes()));

        ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
        messageBytes.write(fileName.getBytes());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedhashCookie.toByteArray());
        messageBytes.write(":".getBytes());
        messageBytes.write(encryptedTimeStamp.toByteArray());

        String hashMessage = Security.hashMessage(new String(messageBytes.toByteArray()));
        ByteString encryptedHashMessage = ByteString.copyFrom(Security.encrypt(privateKey, hashMessage.getBytes()));

        
        UserMainServer.deleteFileRequest request = UserMainServer.deleteFileRequest.newBuilder().setFileId(fileName)
            .setCookie(encryptedhashCookie).setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
        stub.deleteFile(request);
    
        System.out.println("The file " + fileName + " was successfully deleted.");
    }
}
