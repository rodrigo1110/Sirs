package pt.tecnico.grpc.user;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;

import io.grpc.ManagedChannel;
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

import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.net.ssl.SSLException;

import com.google.protobuf.ByteString;

import java.security.*;
import java.security.spec.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.io.DataOutputStream;

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


    public UserImpl(String host, int port){
        host = host;
        port = port;
	}

    public String getCookie(){
        return cookie;
    }

    public static Key getPublicKey(String filename) throws Exception {
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }


    public static Key getPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }


    public void createKeys(String username) throws NoSuchAlgorithmException, Exception{
        //Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        Key privateKey1 = pair.getPrivate();
        Key publicKey1 = pair.getPublic();
        //prints para retirar mais tarde
        //System.out.println("Chave Publica: " + publicKey);
        //System.out.println("Chave privada: " + privateKey);

        DataOutputStream dos = null; 
            try {
                //se der erro, temos de usar funcao que se ja existir ficheiro com este nome, nao cria um novo (a verificacao do user name so e feita depis na bd do lado do server)
                String path = "publicKey/" + username + "-PublicKey";
                dos = new DataOutputStream(new FileOutputStream(path));
                dos.write(publicKey1.getEncoded());
                dos.flush();
            } catch (Exception e) {
                System.out.println("File already exists");
                throw new RuntimeException(e);
            } finally {
                if (dos != null) {
                    try {
                        dos.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            
            try { 
                //se der erro, temos de usar funcao que se ja existir ficheiro com este nome, nao cria um novo (a verificacao do user name so e feita depis na bd do lado do server)
                String path = "privateKey/" + username + "-PrivateKey";
                dos = new DataOutputStream(new FileOutputStream(path));
                dos.write(privateKey1.getEncoded());
                dos.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                if (dos != null)
                    try {
                        dos.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
            }
            //prints para retirar mais tarde
            /*String path = "publicKey/" + username + "-PublicKey";
            String path2 = "privateKey/" + username + "-PrivateKey";
            System.out.println("Public key gerada: " + getPublicKey(path));
            System.out.println("Private key gerada: " + getPrivateKey(path2));*/
    }


    public byte[] encryptKey(byte[] inputArray, Key key) throws Exception {
        byte[] result = {0};
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inputLength = inputArray.length;
        System.out.println("Encrypted bytes:" + inputLength);
        int MAX_ENCRYPT_BLOCK = 117;
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] iteration = {};

        while (inputLength-offSet> 0) {
            if (inputLength-offSet> MAX_ENCRYPT_BLOCK) {
                iteration = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                iteration = cipher.doFinal(inputArray, offSet, inputLength-offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + iteration.length);
            System.arraycopy(iteration, 0, resultBytes, resultBytes.length-iteration.length, iteration.length);
        }

        return resultBytes;
    }


    public byte[] decryptKey(byte[] inputArray, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inputLength = inputArray.length;
        System.out.println("Encrypted bytes:" + inputLength);
        int MAX_ENCRYPT_BLOCK = 128;
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] iteration = {};

        while (inputLength-offSet> 0) {
            if (inputLength-offSet> MAX_ENCRYPT_BLOCK) {
                iteration = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                iteration = cipher.doFinal(inputArray, offSet, inputLength-offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + iteration.length);
            System.arraycopy(iteration, 0, resultBytes, resultBytes.length-iteration.length, iteration.length);
        }

        return resultBytes;
    }
    
    //encrypt with public and private key --> server and user
    public byte[] encrypt(Key key, byte[] text) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            return rsa.doFinal(text); //text.getBytes()

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //derypt with public and private key --> server and user
    public String decrypt(Key key, byte[] buffer) {
        try {
            Cipher rsa;
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, key);
            byte[] value = rsa.doFinal(buffer);
            return new String(value);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String hashMessage(String secretString) throws NoSuchAlgorithmException, NoSuchProviderException{
        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);
        System.out.println("hash text:" + hashtext);
        return hashtext;
    }

    private boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
        String message = new String(Message);
        if((hashMessage(message).compareTo(hashMessage)) == 0)
            return true;
        return false;   
    }

    private String convertToHex(byte[] messageDigest) {
        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);
        return hexText;
    }

    public byte[] getTimeStampBytes(){
        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();
        return Long.toString(timeStampLong).getBytes();
    }

    public void signup(String target){
		
        System.out.println("------------------------------");
        System.out.println("User Registration");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        StringBuilder sb = new StringBuilder("");
        System.out.print("Please, enter your password: ");
		char [] input = System.console().readPassword();
        sb.append(input);
        String password = sb.toString();

        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("------------------------------");

        //---------------------------------------------------------------------------------------
        try{
            createKeys(userName);
            
        }catch(NoSuchAlgorithmException e) {
            System.out.println("No algorithm");
        }catch(Exception e){
            System.out.println("AQUIIIIII");
            throw new RuntimeException(e);
        }
        try{
            
            if(!hasServerPublicKey){
                serverPublicKey = getPublicKey("../server/rsaPublicKey");
                hasServerPublicKey = true;
            }

            String targetPublic = "publicKey/" + userName + "-PublicKey";
            String targetPrivate = "privateKey/" + userName + "-PrivateKey";
            publicKey = getPublicKey(targetPublic);
            privateKey = getPrivateKey(targetPrivate);
            
            ByteString encryptedPassword = ByteString.copyFrom(encrypt(serverPublicKey, password.getBytes()));
            ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

            String path = "publicKey/" + userName + "-PublicKey";
            byte[] clientPublicKeyBytes = Files.readAllBytes(Paths.get(path));
            System.out.println("CHAVE PUBLICA DO CLIENTE TOSTRING");
            System.out.println(new String(clientPublicKeyBytes));
            ByteString encryptedPublicKey = ByteString.copyFrom(encryptKey(clientPublicKeyBytes, serverPublicKey));
            
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(userName.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedPassword.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedTimeStamp.toByteArray());
            
            String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
            ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));


            File tls_cert = new File("../server/tlscert/server.crt");
            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.signUpRequest request = UserMainServer.signUpRequest.newBuilder()
                .setUserName(userName).setPassword(encryptedPassword).setPublicKeyClient(encryptedPublicKey)
                .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
    
            stub.signUp(request);
            
            System.out.println("Successful Registration! Welcome " + userName + ".");
        }
        catch(Exception e){
            System.out.println(e);           
        }
    }


    public void login(String target) throws SSLException{

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
        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("-------- ----------------------");

        try{

            if(!hasServerPublicKey){
                serverPublicKey = getPublicKey("../server/rsaPublicKey");
                hasServerPublicKey = true;
            }
            String targetPublic = "publicKey/" + userName + "-PublicKey";
            String targetPrivate = "privateKey/" + userName + "-PrivateKey";
            publicKey = getPublicKey(targetPublic);
            privateKey = getPrivateKey(targetPrivate);

            ByteString encryptedPassword = ByteString.copyFrom(encrypt(serverPublicKey, password.getBytes()));
            ByteString encryptedTimeStamp = ByteString.copyFrom(encrypt(privateKey, getTimeStampBytes()));

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(userName.getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedPassword.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedTimeStamp.toByteArray());

            String hashMessage = hashMessage(new String(messageBytes.toByteArray()));
            ByteString encryptedHashMessage = ByteString.copyFrom(encrypt(privateKey, hashMessage.getBytes()));

            File tls_cert = new File("../server/tlscert/server.crt");
            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.loginRequest request = UserMainServer.loginRequest.newBuilder().
            setUserName(userName).setPassword(encryptedPassword)
            .setTimeStamp(encryptedTimeStamp).setHashMessage(encryptedHashMessage).build();
    
            UserMainServer.loginResponse response = stub.login(request);

            byte[] cookie = response.getCookie().toByteArray();
            String cookieDecrypted = decrypt(privateKey, cookie);
            byte[] hashCookie = response.getHashCookie().toByteArray();
            String hashCookieDecrypted = decrypt(serverPublicKey, hashCookie);

            if(!verifyMessageHash(cookieDecrypted.getBytes(), hashCookieDecrypted)){
                System.out.println("Response message corrupted.");
                return;
            }
    
            System.out.println(response);
            this.cookie = cookieDecrypted;

            System.out.println("COOKIE: " + cookieDecrypted);

        } catch (Exception e) {
            System.out.println(e);
        }

        System.out.println("Successful Login! Welcome back " + userName + ".");

    }

    public void share(){

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to share: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to share this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username" + counter + ": ");
            counter++;
            userName = System.console().readLine();
            listOfUsers.add(userName);
        }
        //delete de 'x'
        listOfUsers.remove(listOfUsers.size()-1);

        //para testar
        System.out.println("list of users to string: " + listOfUsers.toString());
        System.out.println(listOfUsers.toString());
        System.out.println(listOfUsers.size());

        //chave simetrica (que encriptou o ficheiro) encriptada com a chave publica do (cada um) cliente que tem acesso ao ficheiro


        //try {
            UserMainServer.shareRequest request = UserMainServer.shareRequest.newBuilder().setFileId(fileName).addAllUserName(listOfUsers).setCookie(cookie).build();
    
            stub.share(request);
            System.out.println("The file " + fileName + " was successfully shared.");

            
            /* se o nome de algum user esta mal, este user tem de ser avisado, por fazer!!!! Server envia mensagem a dizer que um nao existe?*/

        /*} catch (SSLException e) {
            e.printStackTrace();
        } */


    }

    public void unshare(){

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to unshare: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        List<String> listOfUsers = new ArrayList<String>();
        String userName = "";  
        System.out.println("Please, enter the usernames of the users you want to unshare this file with.");
        System.out.println("When you are done, press 'x'.");
        Integer counter = 1;
        while(!userName.equals("x")){
            System.out.print("Username" + counter + ": ");
            counter++;
            userName = System.console().readLine();
            listOfUsers.add(userName);
        }
        //delete de 'x'
        listOfUsers.remove(listOfUsers.size()-1);

        //para testar
        System.out.println("list of users to string: " + listOfUsers.toString());
        System.out.println(listOfUsers.toString());
        System.out.println(listOfUsers.size());

       // File tls_cert = new File("../server/tlscert/server.crt");
/*         try {
            final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
         */
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.unshareRequest request = UserMainServer.unshareRequest.newBuilder().setFileId(fileName).addAllUserName(listOfUsers).setCookie(cookie).build();
    
            stub.unshare(request);

            System.out.println("The file " + fileName + " was successfully unshared.");

/*         } catch (SSLException e) {
            e.printStackTrace();
        }  */
    }
    

    public void logout(){
/* 		try {
 */            
        UserMainServer.logoutRequest request = UserMainServer.logoutRequest.newBuilder().setCookie(cookie).build();
        UserMainServer.logoutResponse response = stub.logout(request);

            //channel.shutdownNow();
/*         } catch (SSLException e) {
            e.printStackTrace();
        }  */

        cookie = "";
        System.out.println("Successful logout.");
    }

    public void download(){
		
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to download: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");


        //File tls_cert = new File("../server/tlscert/server.crt");
        //try {
            /*final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);*/
            UserMainServer.downloadRequest request = UserMainServer.downloadRequest.newBuilder().setFileId(fileName).setCookie(cookie).build();
    
            UserMainServer.downloadResponse response = stub.download(request);

            try {
                File file = new File("downloads/" + fileName);

                if (file.createNewFile()) {

                  System.out.println("New file created: " + file.getName());
    
                  OutputStream os = new FileOutputStream(file);
      
                  os.write(response.getFileContent().toByteArray());
          
                  os.close();

                  System.out.println("Successful Download! You can find your downloaded file in your downloads directory.");

                } 
                
                else {
                  System.out.println("File already exists.");
                  //devemos apagar e criar um novo?
                }
              
            } catch(Exception e){
                System.out.println(e.toString());
            }
                
        /*} catch (SSLException e) {
            e.toString();
        } */


    }
    
    public void upload(){

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to upload: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        try{
        
            Path path = Paths.get("uploads/" + fileName);

            byte[] byteArray = Files.readAllBytes(path);

            ByteString bytestring = ByteString.copyFrom(byteArray);

            //a funcao de hash de ficheiros recebe argumento do tipo ByteString
            //encripta a hash com a chave privada do cliente
            //encripta o bytestring com chave simetrica (gerada por aes - 256, block cbc)
            //encriptar chave simetrica com chave publica do servidor 

            //try {
                
                UserMainServer.uploadRequest request = UserMainServer.uploadRequest.newBuilder().setFileId(fileName).setFileContent(bytestring).setCookie(cookie).build();
        
                stub.upload(request);

                System.out.println("Successful Upload!");

                    
            /*} catch (SSLException e) {
                e.toString();
            } */ 
        } catch (Exception e){
            if(e.getClass().toString().compareTo("class java.nio.file.NoSuchFileException") == 0){
                System.out.println("That file does not exist in your uploads directory.");
            }
            else{
                System.out.println(e.toString());
            }
        } 

    }


    public void deleteUser(String target){
            
        System.out.println("------------------------------");
        System.out.print("Please, enter the username you want to delete: ");
        String userName = System.console().readLine();
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

        File tls_cert = new File("../server/tlscert/server.crt");
        try {
            channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            stub = UserMainServerServiceGrpc.newBlockingStub(channel);

            UserMainServer.deleteUserRequest request = UserMainServer.deleteUserRequest.newBuilder().setUserName(userName).setPassword(password).build();
            UserMainServer.deleteUserResponse response = stub.deleteUser(request);

            System.out.println("User deleted successfully!");


        } catch (SSLException e) {
            e.printStackTrace();
        }
    
    }

    public void deleteFile(){

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to delete: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");
        
        UserMainServer.deleteFileRequest request = UserMainServer.deleteFileRequest.newBuilder().setFileId(fileName).setCookie(cookie).build();
        UserMainServer.deleteFileResponse response = stub.deleteFile(request);
    
        System.out.println("The file " + fileName + " was successfully deleted.");

    }

}
