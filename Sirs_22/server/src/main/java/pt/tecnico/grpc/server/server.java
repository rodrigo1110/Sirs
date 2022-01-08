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

import javax.lang.model.util.ElementScanner6;
import javax.net.ssl.SSLException;
import java.io.File;

public class server {

	//-------------- Main function only------------------

	private static boolean clientActive = false;
	private static int port = 8090;
	private static int instance;
	private static Server server;
	private static String backupHostName;
	private static BindableService impl;
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
		
		if(instance==1){
			try{
				createClient(instance,backupHostName);
			} catch (StatusRuntimeException e){
				System.err.println("Backup Server isn't running initially.");
				System.exit(-1); //Instead of exiting assume as normal behavior later?(backup may be compromissed/inexistent since beginning of program?)
			} catch (SSLException e){
				System.err.println("SSL error with description: " + e);
				System.exit(-1);
			} catch (IOException ex){
				System.err.println("IOException with message: " + ex.getMessage() + " and cause:" + ex.getCause());
				System.exit(-1);
			}
		}
		try{
			createServer(instance);
		} catch (IOException ex){
			System.err.println("IOException with message: " + ex.getMessage() + " and cause:" + ex.getCause());
			System.exit(-1);
		}

		// Server threads are running in the background.
		System.out.println("Server started");
		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();
	}


	public static void createServer(int instance) throws IOException{
		if(instance==1){
			impl = new mainServerServiceImpl();
			server = ServerBuilder.forPort(port + instance).useTransportSecurity(new File("tlscert/server.crt"),
        	new File("tlscert/server.pem")).addService(impl).build();
			server.start();
		}
		else{
			impl = new backupServerServiceImpl(instance);
			server = ServerBuilder.forPort(port + instance).useTransportSecurity(new File("tlscert/backupServer.crt"), 
        	new File("tlscert/backupServer.pem")).addService(impl).build();
			server.start();
		}
	}


	public static void createClient(int instance, String host) throws StatusRuntimeException, SSLException{
		clientActive = false;
		final String target = host + ":" + (port + instance + 1);
		File tls_cert = new File("tlscert/backupServer.crt");
		
		channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
		stub = MainBackupServerServiceGrpc.newBlockingStub(channel);
		clientActive = true;
		
		//---just for testing, delete laters---
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

	public MainBackupServerServiceGrpc.MainBackupServerServiceBlockingStub getStub(){
		return stub;
	}

	public boolean getClientActive(){
		return clientActive;
	}
}
