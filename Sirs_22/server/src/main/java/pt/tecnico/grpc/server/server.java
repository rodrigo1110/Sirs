package pt.tecnico.grpc.server;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import java.io.File;

public class server {

	//-------------- Main function only------------------

	private static int port;
	private static int instance;

	public static void main(String[] args) throws Exception {
		
		System.out.println(server.class.getSimpleName());

		// Print received arguments.
		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		//Check arguments.
		if (args.length != 1) {
			System.err.println("Invalid Number of Arguments");
			System.err.printf("Usage: java %s instance_of_server%n", server.class.getName());
			return;
		} 

		instance = Integer.valueOf(args[0]);
		port = 8090 + instance;

		BindableService impl;
		Server server;
		if(instance==1){
			impl = new mainServerServiceImpl();
			server = ServerBuilder.forPort(port).useTransportSecurity(new File("tlscert/server.crt"),
        	new File("tlscert/server.pem")).addService(impl).build();
		}
		else{
			impl = new backupServerServiceImpl(instance);
			server = ServerBuilder.forPort(port).useTransportSecurity(new File("tlscert/server.crt"), //TODO add certificate and key for backup server
        	new File("tlscert/server.pem")).addService(impl).build();
		}

		server.start();

		// Server threads are running in the background.
		System.out.println("Server started");

		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();
	}

}
