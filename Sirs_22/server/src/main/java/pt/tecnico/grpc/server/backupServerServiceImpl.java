package pt.tecnico.grpc.server;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.server.backupServer;

import static io.grpc.Status.*;
import io.grpc.StatusRuntimeException;
import java.io.IOException;
import javax.net.ssl.SSLException;

import io.grpc.stub.StreamObserver;

public class backupServerServiceImpl extends MainBackupServerServiceGrpc.MainBackupServerServiceImplBase{
    
	//--------------------------mainServer-backupServer communication implementation--------------------------
	
	private int instanceNumber;
	private backupServer server = new backupServer();
	private server listeningServer = new server();

	public backupServerServiceImpl(int instance_number){
		instanceNumber = instance_number;
	}
	
	@Override
	public void greeting(MainBackupServer.HelloRequest request, StreamObserver<MainBackupServer.HelloResponse> responseObserver) {
		System.out.println(request);

		MainBackupServer.HelloResponse response = MainBackupServer.HelloResponse.newBuilder()
				.setGreeting(server.greet(request.getName()) + Integer.toString(instanceNumber)).build();
		responseObserver.onNext(response);
		responseObserver.onCompleted();
		//listeningServer.getServer().shutdown(); use later for killing backup server in case of ransomware attack on main or backup server
	}


	@Override
	public void heartbeat(MainBackupServer.heartbeatRequest request, StreamObserver<MainBackupServer.heartbeatResponse> responseObserver) {
		try{
			MainBackupServer.heartbeatResponse response = server.heartbeat(instanceNumber);
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void promote(MainBackupServer.promoteRequest request, StreamObserver<MainBackupServer.promoteResponse> responseObserver) {
		try{
			if(request.getTargetInstance() == instanceNumber)
				server.promote();
			
			MainBackupServer.promoteResponse response = MainBackupServer.promoteResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();

			if(request.getTargetInstance() == instanceNumber){
				//listeningServer.getServer().shutdown(); use later for killing backup server 
				//listeningServer.createClient(instanceNumber,localhost); use later for creating new client to new principal backup
				//listeningServer.createServer(instanceNumber) use later for server promotion from principal backup to mainServer
			}
		}
		/*catch (StatusRuntimeException e){   //Do something about these exceptions later or just delete them because they don't alter system in any way
		} catch (SSLException e){
		}*/ catch (IOException ex){
			System.err.println("IOException with message: " + ex.getMessage() + " and cause:" + ex.getCause());
			System.exit(-1);
		} catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void write(MainBackupServer.writeRequest request, StreamObserver<MainBackupServer.writeResponse> responseObserver) {
		try{
			server.write(request.getUsername(),request.getField(),request.getValue(),request.getSequence());

			MainBackupServer.writeResponse response = MainBackupServer.writeResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void writeFile(MainBackupServer.writeFileRequest request, StreamObserver<MainBackupServer.writeFileResponse> responseObserver) {
		try{
			server.writeFile(request.getFileName(), request.getFileContent(), request.getFileOwner());

			MainBackupServer.writeFileResponse response = MainBackupServer.writeFileResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void read(MainBackupServer.readRequest request, StreamObserver<MainBackupServer.readResponse> responseObserver) {
		try{
			MainBackupServer.readResponse response  = server.read(request.getUsername(),request.getField());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void readFile(MainBackupServer.readFileRequest request, StreamObserver<MainBackupServer.readFileResponse> responseObserver) {
		try{
			MainBackupServer.readFileResponse response  = server.readFile(request.getUsername(),request.getFileId());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void writeUser(MainBackupServer.writeUserRequest request, StreamObserver<MainBackupServer.writeUserResponse> responseObserver) {
		try{
			server.writeUser(request.getUsername(),request.getHashPassword(),request.getSalt());

			MainBackupServer.writeUserResponse response = MainBackupServer.writeUserResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	
	@Override
	public void writePermission(MainBackupServer.writePermissionRequest request, StreamObserver<MainBackupServer.writePermissionResponse> responseObserver) {
		try{
			server.writePermission(request.getFileName(),request.getUserName());

			MainBackupServer.writePermissionResponse response = MainBackupServer.writePermissionResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void removePermission(MainBackupServer.removePermissionRequest request, StreamObserver<MainBackupServer.removePermissionResponse> responseObserver) {
		try{
			server.removePermission(request.getFileName(),request.getUserName());

			MainBackupServer.removePermissionResponse response = MainBackupServer.removePermissionResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void updateCookie(MainBackupServer.updateCookieRequest request, StreamObserver<MainBackupServer.updateCookieResponse> responseObserver) {
		try{
			server.updateCookie(request.getUserName(), request.getCookie());

			MainBackupServer.updateCookieResponse response = MainBackupServer.updateCookieResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void deleteFile(MainBackupServer.deleteFileRequest request, StreamObserver<MainBackupServer.deleteFileResponse> responseObserver) {
		try{
			server.deleteFile(request.getFileName());

			MainBackupServer.deleteFileResponse response = MainBackupServer.deleteFileResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void deleteUser(MainBackupServer.deleteUserRequest request, StreamObserver<MainBackupServer.deleteUserResponse> responseObserver){
		try{
			server.deleteUser(request.getUserName());

			MainBackupServer.deleteUserResponse response = MainBackupServer.deleteUserResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}
}
