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
import java.io.*;
import java.nio.file.Files;

import java.util.Arrays;

import javax.net.ssl.SSLException;

import com.google.protobuf.ByteString;


public class UserImpl {
    private String host;
	private int port;
    private String cookie = "";


    public UserImpl(String host, int port){
        host = host;
        port = port;
	}

    public void signup(String target){
		
        System.out.println("------------------------------");
        System.out.println("User Registration");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        System.out.print("Please, enter your password: ");
        String password = System.console().readLine();
        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("------------------------------");


        //codigo hash da password + encriptar com privada do cliente
        //criar chave publica e provada do novo user. Privada fica (aqui) no cliente. Publica vai para onde esta a publica do servidor

        File tls_cert = new File("../server/tlscert/server.crt");
        try {
            final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.signUpRequest request = UserMainServer.signUpRequest.newBuilder().setUserName(userName).setPassword(password).build();
    
            stub.signUp(request);
            
            System.out.println("Successful Registration! Welcome " + userName + ".");

        } catch (SSLException e) {
            // se a excecao e a do user duplicado, como mostrar apenas texto da mensagem ao utilizador?

            //e.printStackTrace();
            //e.getMessage();
            //e.getClass();
        }
    }
    public void login(String target) throws SSLException{

        System.out.println("------------------------------");
        System.out.print("Please, enter your username: ");
        String userName = System.console().readLine();
        System.out.println("You entered the username " + userName);
        System.out.println("------------------------------");

        System.out.print("Please, enter your password: ");
        String password = System.console().readLine();
        /* Para apagar depois, claro */
        System.out.println("You entered the password " + password);
        System.out.println("-------- ----------------------");


        //codigo hash da password + encriptar com privada do cliente

        //(password) +servidor , (password)- cliente)+ servidor

        File tls_cert = new File("../server/tlscert/server.crt");
        try {
            final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.loginRequest request = UserMainServer.loginRequest.newBuilder().setUserName(userName).setPassword(password).build();
    
            UserMainServer.loginResponse response = stub.login(request);
    
            System.out.println(response);
            this.cookie = response.getCookie();

        } catch (SSLException e) {
            e.printStackTrace();
        }

        System.out.println("Successful Login! Welcome back " + userName + ".");

    }

    public void share(String target){

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

        File tls_cert = new File("../server/tlscert/server.crt");
        try {
            final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.shareRequest request = UserMainServer.shareRequest.newBuilder().setFileId(fileName).addAllUserName(listOfUsers).setCookie("cookieee").build();
    
            stub.share(request);
            
            /* se o nome de algum user esta mal, este user tem de ser avisado, por fazer!!!! Server envia mensagem a dizer que um nao existe?*/

        } catch (SSLException e) {
            e.printStackTrace();
        } 


    }

    public void logout(String id){
		
        
    }

    public void download(String target){
		
        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to download: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");


        File tls_cert = new File("../server/tlscert/server.crt");
        try {
            final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
        
            UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
            UserMainServer.downloadRequest request = UserMainServer.downloadRequest.newBuilder().setFileId(fileName).setCookie(this.cookie).build();
    
            UserMainServer.downloadResponse response = stub.download(request);

            try {
                File file = new File(fileName);

                if (file.createNewFile()) {

                  System.out.println("New file created: " + file.getName());
    
                  OutputStream os = new FileOutputStream(file);
      
                  os.write(response.getFileContent().toByteArray());
          
                  os.close();
                } 
                
                else {
                  System.out.println("File already exists.");
                  //devemos apagar e criar um novo?
                }
              
            } catch(Exception e){
                System.out.println(e.toString());
            }
                
        } catch (SSLException e) {
            e.toString();
        } 

        System.out.println("Successful Download! You can find your downloaded file in...");

    }
    
    public void upload(String target){

        System.out.println("------------------------------");
        System.out.print("Please, enter the name of the file you want to upload: ");
        String fileName = System.console().readLine();
        System.out.println("You entered the file " + fileName);
        System.out.println("------------------------------");

        try{
        
            Path path = Paths.get("files/" + fileName);

            byte[] byteArray = Files.readAllBytes(path);

            ByteString bytestring = ByteString.copyFrom(byteArray);

            File tls_cert = new File("../server/tlscert/server.crt");

            try {
                final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
            
                UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
                UserMainServer.uploadRequest request = UserMainServer.uploadRequest.newBuilder().setFileId(fileName).setFileContent(bytestring).setCookie(cookie).build();
        
                stub.upload(request);
                    
            } catch (SSLException e) {
                e.toString();
            }  
        } catch (Exception e){
            System.out.println(e.toString());
        }

        System.out.println("Successful Upload!");
    }
}
