package pt.tecnico.grpc.user;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;

import java.util.Scanner;
import java.util.concurrent.TimeUnit;
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

		System.out.printf("Received %d arguments%n", args.length);

		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		if (args.length != 3) {
			System.err.println("Invalid Number of Arguments");
			myObj.close();
			return;
		} 

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		final String backupHost = args[2];
		final String target = host + ":" + port;

		String[] command;
		String str;
		Boolean serverLeft = true;
		int attempts = 0;

		File tls_cert = new File("../server/tlscert/server.crt");
		final ManagedChannel channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();

		UserImpl user = new UserImpl(host, port);

		System.out.println();

		System.out.println("==========================");
		System.out.print("= Remote Document Access =\n");
		System.out.println("==========================");

		System.out.println("Type 'help' to see avaliable operations.");

		System.out.println();

		while(myObj.hasNext()){

			System.out.print("> ");
			str = myObj.nextLine();
			command = str.split("\\s+");
			
			if(user.getCookie().compareTo("") == 0){

				try{
					switch (command[0]) {
						case "signup":
							user.signup();
							break;
						case "login":
							user.login();
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

					if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){

						System.out.println("Ransmomware attack detected.");

						if(!serverLeft)
							System.exit(0);

						user.setTarget(backupHost, port + 2);
						TimeUnit.SECONDS.sleep(1);
						serverLeft = false;
					}
					else if((e.getMessage()).compareTo("INVALID_ARGUMENT: Wrong password.") == 0){

						System.out.println(e.getStatus().getDescription());

						attempts++;
						
						if(attempts > 2){
							System.out.println("You have to wait " + (attempts-2)*5 + " seconds to try to login again.");
							TimeUnit.SECONDS.sleep(attempts*5);
							System.out.println("You can login now.");
						}
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
							if((attempts*5) > 0){
								System.out.println("Waiting " + (attempts)*5 + " seconds.");
								TimeUnit.SECONDS.sleep(attempts*5);
							}
							break;
						case "createFile":
							user.createFile();
							break;
						case "editFile":
							user.editFile();
							break;
						case "showRemoteFiles":
							user.showFiles();
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
							System.out.printf(" - createFile\n");
							System.out.printf(" - editFile\n");
							System.out.printf(" - showRemoteFiles\n");
							System.out.printf(" - download\n");
							System.out.printf(" - upload\n"); 
							System.out.printf(" - share\n"); 
							System.out.printf(" - unshare\n"); 
							System.out.printf(" - deleteUser\n"); 
							System.out.printf(" - deleteFile\n"); 
							System.out.printf(" - logout\n");
							System.out.printf(" - exit\n");
							break;
						case "exit":
							System.exit(0);
						default: 
							System.out.printf("Message not found%n");
							break;
					}
				} catch(StatusRuntimeException e){

					if((e.getStatus().getCode().equals(Status.DATA_LOSS.getCode()))){

						System.out.println("Ransmomware attack detected.");

						if(!serverLeft)
							System.exit(0);

						user.setTarget(backupHost, port+2);
						TimeUnit.SECONDS.sleep(1);
						serverLeft = false;
					}
					else{
						System.out.println(e.getStatus().getDescription());
					}
				} 
				catch(Exception e){
					System.out.println(e);
				}
			}
		}
		
		myObj.close();

		channel.shutdownNow();
	}
}
