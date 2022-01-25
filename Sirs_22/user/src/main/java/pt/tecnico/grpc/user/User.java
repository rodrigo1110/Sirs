package pt.tecnico.grpc.user;

/* these imported classes are generated by the hello-world-server contract */
import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;

import java.util.Scanner;
import java.io.DataOutputStream;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import java.io.File;


public class User {

	public static void main(String[] args) throws Exception {
		System.out.println(User.class.getSimpleName());
		Scanner myObj = new Scanner(System.in);

		// receive and print arguments
		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		if (args.length != 2) {
			System.err.println("Invalid Number of Arguments");
			myObj.close();
			return;
		} 

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		final String target = host + ":" + port;

		String[] command;
		String str;
		final String id = "aluno";
		final String password = "password";

		// Channel is the abstraction to connect to a service endpoint
		File tls_cert = new File("../server/tlscert/server.crt");
		final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();

		UserImpl user = new UserImpl(host, port);

		System.out.println("==========================");
		System.out.print("= Remote Document Access =\n");
		System.out.println("==========================");

		System.out.println("Type 'help' to see avaliable operations.");

		
		while(myObj.hasNext()){
			System.out.print("> ");
			str = myObj.nextLine();
			command = str.split("\\s+");

			//avaliableOperations(user.getCookie());
			
			if(user.getCookie().compareTo("") == 0){

				try{
					switch (command[0]) {
						case "signup":
							user.signup(target);
							break;
						case "login":
							user.login(target);
							break;
						case "help":
							System.out.printf("Avaliable operations:\n");
							System.out.printf(" - signup\n");
							System.out.printf(" - login\n");
							System.out.printf(" - exit\n");
							break;
						case "exit":
							System.exit(0);
						default: 
							System.out.printf("That operation is unavailable.%n");
							break;
					}
				} catch(StatusRuntimeException e){
					if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){//ransomware
						System.out.println("Ransmomware");
					}
					else{
						System.out.println(e.getStatus().getDescription());
					}
				}
			}
		 	else{

				try{
					switch (command[0]) {
						case "logout":
							user.logout();
							break;
						case "download":
							user.download();
							break;
						case "upload":
							user.upload();
							break;
						case "share":
							user.share();
							break;
						case "unshare":
							user.unshare();
							break;
						case "deleteUser":
							user.deleteUser();
							break;
						case "deleteFile":
							user.deleteFile();
							break;
						case "help":
							System.out.printf("Avaliable operations:\n");
							System.out.printf(" - logout\n");
							System.out.printf(" - download\n");
							System.out.printf(" - upload\n"); 
							System.out.printf(" - share\n"); 
							System.out.printf(" - unshare\n"); 
							System.out.printf(" - deleteUser\n"); 
							System.out.printf(" - deleteFile\n"); 
							System.out.printf(" - exit\n");
							break;
						case "exit":
							System.exit(0);
						default: 
							System.out.printf("Message not found%n");
							break;
					}
				} catch(StatusRuntimeException e){
					if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){//ransomware
						System.out.println("Ransmomware");
					}
					else{
						System.out.println(e.getStatus().getDescription());
					}
				} catch(Exception e){
					System.out.println(e);
				}
			}
		}
		
		myObj.close();
		/*public static void createConnection(String host, int port) throws StatusRuntimeException, SSLException{

			final String target = host + ":" + (port + instance + 1);
			File tls_cert = new File("tlscert/backupServer.crt");
			
			//---just for testing, delete laters---
			
		}*/

		// It is up to the client to determine whether to block the call
		// Here we create a blocking stub, but an async stub,
		// or an async stub with Future are always possible.
		UserMainServerServiceGrpc.UserMainServerServiceBlockingStub stub = UserMainServerServiceGrpc.newBlockingStub(channel);
		UserMainServer.HelloRequest request = UserMainServer.HelloRequest.newBuilder().setName("friend").build();


		// Finally, make the call using the stub
		UserMainServer.HelloResponse response = stub.greeting(request);

		// HelloResponse has auto-generated toString method that shows its contents
		System.out.println(response);

		// A Channel should be shutdown before stopping the process.
		channel.shutdownNow();
	}

}
