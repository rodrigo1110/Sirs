package pt.tecnico.grpc.server;

import pt.tecnico.grpc.MainBackupServer;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;
import pt.tecnico.grpc.server.backupServer;
import pt.tecnico.grpc.server.exceptions.BackupRansomwareAttackException;

import static io.grpc.Status.*;

import io.grpc.Server;
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
	public void promote(MainBackupServer.promoteRequest request, StreamObserver<MainBackupServer.promoteResponse> responseObserver) {
		try{
			MainBackupServer.promoteResponse response = MainBackupServer.promoteResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();

			listeningServer.createMainServer(); //server promotion from backup to mainServer

		} catch (Exception e){
			System.out.println(e.getMessage());
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void writeFile(MainBackupServer.writeFileRequest request, StreamObserver<MainBackupServer.writeFileResponse> responseObserver) {
		try{
			server.writeFile(request.getFileName(), request.getFileContent(), request.getFileOwner(),
			request.getHash());

			MainBackupServer.writeFileResponse response = MainBackupServer.writeFileResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void writeUser(MainBackupServer.writeUserRequest request, StreamObserver<MainBackupServer.writeUserResponse> responseObserver) {
		try{
			server.writeUser(request.getUsername(),request.getHashPassword(),request.getSalt(),
			request.getPublicKey(), request.getHash());

			MainBackupServer.writeUserResponse response = MainBackupServer.writeUserResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	
	@Override
	public void writePermission(MainBackupServer.writePermissionRequest request, StreamObserver<MainBackupServer.writePermissionResponse> responseObserver) {
		try{
			server.writePermission(request.getFileName(), request.getUserName(), request.getSymmetricKey(),
			request.getInitializationVector(), request.getHash());

			MainBackupServer.writePermissionResponse response = MainBackupServer.writePermissionResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
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
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void updateCookie(MainBackupServer.updateCookieRequest request, StreamObserver<MainBackupServer.updateCookieResponse> responseObserver) {
		try{
			server.updateCookie(request.getUserName(), request.getCookie(), request.getHash());

			MainBackupServer.updateCookieResponse response = MainBackupServer.updateCookieResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void updateFile(MainBackupServer.updateFileRequest request, StreamObserver<MainBackupServer.updateFileResponse> responseObserver) {
		try{
			server.updateFile(request.getFileName(), request.getFileContent(), request.getHash());

			MainBackupServer.updateFileResponse response = MainBackupServer.updateFileResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
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
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
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
		catch (BackupRansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
			listeningServer.getServer().shutdown(); 
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}
}
