package pt.tecnico.grpc.server;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;


import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ManagedChannel;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.StatusRuntimeException;

import java.io.IOException;
import javax.net.ssl.SSLException;
import java.io.File;

public class server {

	//-------------- Main function only------------------

	private static int port;
	private static int instance;
	private static Server server;
	private static String backupHostName;
	private static ManagedChannel channel;
	private static MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub stub;

	public static void main(String[] args) throws StatusRuntimeException, Exception {
		
		System.out.println(server.class.getSimpleName());

		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		if (args.length != 2) {
			System.err.println("Invalid Number of Arguments");
			System.err.printf("Usage: java %s instance_of_server backup server's host name %n", server.class.getName());
			return;
		} 

		instance = Integer.valueOf(args[0]);
		backupHostName = args[1];
		port = 8090 + instance;
		BindableService impl;
		
		if(instance==1){
			impl = new mainServerServiceImpl();
			server = ServerBuilder.forPort(port).useTransportSecurity(new File("tlscert/server.crt"),
        	new File("tlscert/server.pem")).addService(impl).build();

			try{
			createClient();
			server.start();
			} catch (StatusRuntimeException e){
				System.err.println("Backup Server isn't running initially.");
				System.exit(-1);
			} catch (SSLException e){
				System.err.println("SSL error with description: " + e);
				System.exit(-1);
			}
		}

		else{
			impl = new backupServerServiceImpl(instance);
			server = ServerBuilder.forPort(port).useTransportSecurity(new File("tlscert/backupServer.crt"), 
        	new File("tlscert/backupServer.pem")).addService(impl).build();
			server.start();
		}

		// Server threads are running in the background.
		System.out.println("Server started");
		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();
	}


	public static void createClient() throws StatusRuntimeException, SSLException{
		final String target = backupHostName + ":" + (port + 1);
		File tls_cert = new File("tlscert/backupServer.crt");
		
		channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
		stub = MainBackupServerServiceGrpc.newBlockingStub(channel);
		
		//---just for testing---
		MainBackupServer.HelloRequest request = MainBackupServer.HelloRequest.newBuilder().setName("friend").build();
		MainBackupServer.HelloResponse response = stub.greeting(request);
		System.out.println(response);
	}


	public Server getServer(){
		return server;
	}

	public ManagedChannel getChannel(){
		return channel;
	}
}
