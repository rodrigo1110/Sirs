package pt.tecnico.grpc.server;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.server.backupServer;

import io.grpc.stub.StreamObserver;

public class backupServerServiceImpl extends MainBackupServerServiceGrpc.MainBackupServerServiceImplBase{
    
	//--------------------------mainServer-backupServer communication implementation--------------------------
	
	private int instanceNumber;
	private backupServer server = new backupServer();

	public backupServerServiceImpl(int instance_number){
		instanceNumber = instance_number;
	}
	
	@Override
	public void greeting(MainBackupServer.HelloRequest request, StreamObserver<MainBackupServer.HelloResponse> responseObserver) {

		// HelloRequest has auto-generated toString method that shows its contents
		System.out.println(request);

		// You must use a builder to construct a new Protobuffer object
		MainBackupServer.HelloResponse response = MainBackupServer.HelloResponse.newBuilder()
				.setGreeting(server.greet(request.getName()) + Integer.toString(instanceNumber)).build();

		// Use responseObserver to send a single response back
		responseObserver.onNext(response);

		// When you are done, you must call onCompleted
		responseObserver.onCompleted();
	}
}
