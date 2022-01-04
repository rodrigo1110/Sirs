package pt.tecnico.grpc.server;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;

public class server {

	/** Server host port. */
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

		//port = Integer.valueOf(args[0]);
		instance = Integer.valueOf(args[0]);
		port = 8090 + instance;
		final BindableService impl = new serverServiceImpl();

		// Create a new server to listen on port.
		Server server = ServerBuilder.forPort(port).addService(impl).build();
		// Start the server.
		server.start();
		// Server threads are running in the background.
		System.out.println("Server started");

		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();
	}

}
