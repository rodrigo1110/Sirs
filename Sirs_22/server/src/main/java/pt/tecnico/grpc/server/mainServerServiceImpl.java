package pt.tecnico.grpc.server;

/* these imported classes are generated by the hello-world-server contract */
import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;
import pt.tecnico.grpc.MainBackupServerServiceGrpc;

import pt.tecnico.grpc.server.mainServer;
import pt.tecnico.grpc.server.server;
import pt.tecnico.grpc.server.exceptions.*;
import io.grpc.stub.StreamObserver;
import static io.grpc.Status.*;

public class mainServerServiceImpl extends UserMainServerServiceGrpc.UserMainServerServiceImplBase {

	//--------------------------user-mainServer communication implementation--------------------------
	
	private server listeningServer = new server();
	private mainServer server = new mainServer(listeningServer.getClientActive(),listeningServer.getChannel(), listeningServer.getStub());
	



	@Override
	public void greeting(UserMainServer.HelloRequest request, StreamObserver<UserMainServer.HelloResponse> responseObserver) {
		System.out.println(request);

		UserMainServer.HelloResponse response = UserMainServer.HelloResponse.newBuilder()
				.setGreeting(server.greet(request.getName())).build();
		responseObserver.onNext(response);
		responseObserver.onCompleted();
		//listeningServer.getServer().shutdown(); use later for killing main server in case of ransomware attack
		//listeningServer.getChannel().shutdown() use later for killing main server's client channel in case of ransomware attack
	}


	@Override 
	public void signUp(UserMainServer.signUpRequest request, StreamObserver<UserMainServer.signUpResponse> responseObserver){
		try{
			server.signUp(request.getUserName(), request.getPassword(), request.getPublicKeyClient(),
			request.getTimeStamp(), request.getHashMessage());

			UserMainServer.signUpResponse response = UserMainServer.signUpResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		} 
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void login(UserMainServer.loginRequest request, StreamObserver<UserMainServer.loginResponse> responseObserver){
		try{
			UserMainServer.loginResponse response = server.login(request.getUserName(), request.getPassword(), request.getTimeStamp(),
			request.getHashMessage());

			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void logout(UserMainServer.logoutRequest request, StreamObserver<UserMainServer.logoutResponse> responseObserver){
		try{
			server.logout(request.getCookie(), request.getTimeStamp(), request.getHashMessage());
			
			UserMainServer.logoutResponse response = UserMainServer.logoutResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void upload(UserMainServer.uploadRequest request, StreamObserver<UserMainServer.uploadResponse> responseObserver){
		try{
			server.upload(request.getFileId(),request.getCookie(),request.getFileContent(), request.getSymmetricKey(), 
			request.getInitializationVector(), request.getTimeStamp(),request.getHashMessage());

			UserMainServer.uploadResponse response = UserMainServer.uploadResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void download(UserMainServer.downloadRequest request, StreamObserver<UserMainServer.downloadResponse> responseObserver){
		try{
			UserMainServer.downloadResponse response = server.download(request.getFileId(),
			request.getCookie(),request.getTimeStamp(),request.getHashMessage());
			
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void share(UserMainServer.shareRequest request, StreamObserver<UserMainServer.shareResponse> responseObserver){
		try{
			UserMainServer.shareResponse response = server.share(request.getFileId(),request.getCookie(),request.getUserNameList(),
				request.getTimeStamp(),request.getHashMessage());
			responseObserver.onNext(response); 
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void shareKey(UserMainServer.shareKeyRequest request, StreamObserver<UserMainServer.shareKeyResponse> responseObserver){
		try{
			UserMainServer.shareKeyResponse response = server.shareKey(request.getSymmetricKeyList(), request.getInitializationVectorList(),
			request.getUserNamesList(), request.getFileId(), request.getTimeStamp(), request.getHashMessage());

			responseObserver.onNext(response); 
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void unshare(UserMainServer.unshareRequest request, StreamObserver<UserMainServer.unshareResponse> responseObserver){
		try{
			server.unshare(request.getFileId(),request.getCookie(),request.getUserNameList(),request.getTimeStamp(),request.getHashMessage());

			UserMainServer.unshareResponse response = UserMainServer.unshareResponse.newBuilder().build();
			responseObserver.onNext(response); 
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override 
	public void deleteUser(UserMainServer.deleteUserRequest request, StreamObserver<UserMainServer.deleteUserResponse> responseObserver){
		try{
			server.deleteUser(request.getUserName(),request.getPassword(),request.getTimeStamp(),request.getHashMessage());

			UserMainServer.deleteUserResponse response = UserMainServer.deleteUserResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override 
	public void deleteFile(UserMainServer.deleteFileRequest request, StreamObserver<UserMainServer.deleteFileResponse> responseObserver){
		try{
			server.deleteFile(request.getFileId(),request.getCookie(),request.getTimeStamp(),request.getHashMessage());

			UserMainServer.deleteFileResponse response = UserMainServer.deleteFileResponse.newBuilder().build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (RansomwareAttackException e){
			responseObserver.onError(DATA_LOSS.withDescription(e.getMessage()).asRuntimeException());
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

}
