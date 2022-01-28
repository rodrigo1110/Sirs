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

	private static boolean clientActive = false;
	private static int port = 8090;
	private static int instance;
	private static String dbName;
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

		if ( (args.length < 2) || ((args.length != 3) && (Integer.valueOf(args[1]) == 1))) {
			System.err.println("Invalid Number of Arguments");
			System.err.printf("Arguments Required: DBName instance_of_server backup_server's_host_name %n", server.class.getName());
			return;
		} 

		dbName = args[0];
		instance = Integer.valueOf(args[1]);
		
		if(instance==1)
			backupHostName = args[2];
		
		if(instance==1){
			try{
				createClient(backupHostName);
			} catch (StatusRuntimeException e){
				System.err.println("Backup Server isn't running initially.");
				System.exit(-1); 
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
		} 
		catch (IOException ex){
			System.err.println("IOException with message: " + ex.getMessage() + " and cause:" + ex.getCause());
			System.exit(-1);
		}

		System.out.println("Server started.");

		server.awaitTermination();
	}


	public static void createServer(int instance) throws IOException{
		if(instance==1){
			impl = new mainServerServiceImpl(dbName);
			server = ServerBuilder.forPort(port + 1).useTransportSecurity(new File("tlscert/server.crt"),
        	new File("tlscert/server.pem")).addService(impl).build();
			server.start();
		}
		else{
			impl = new backupServerServiceImpl(instance, dbName);
			server = ServerBuilder.forPort(port + 2).useTransportSecurity(new File("tlscert/backupServer.crt"), 
        	new File("tlscert/backupServer.pem")).addService(impl).build();
			server.start();
		}
	}

	public void createMainServer(String db_name) throws IOException{
		impl = new mainServerServiceImpl(db_name);
		server = ServerBuilder.forPort(port + 3).useTransportSecurity(new File("tlscert/server.crt"),
		new File("tlscert/server.pem")).addService(impl).build();
		server.start();
	}

	public static void createClient(String host) throws StatusRuntimeException, SSLException{

		clientActive = false;
		final String target = host + ":" + (port + 2);
		File tls_cert = new File("tlscert/backupServer.crt");
		
		channel = NettyChannelBuilder.forTarget(target).sslContext(GrpcSslContexts.forClient().trustManager(tls_cert).build()).build();
		stub = MainBackupServerServiceGrpc.newBlockingStub(channel);
		clientActive = true;
	}
	

	public Server getServer(){
		return server;
	}

	public String getDBName(){
		return dbName;
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
