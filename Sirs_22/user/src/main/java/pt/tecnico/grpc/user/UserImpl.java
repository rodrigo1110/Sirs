package pt.tecnico.grpc.user;

import pt.tecnico.grpc.UserMainServer;
import pt.tecnico.grpc.UserMainServerServiceGrpc;

public class UserImpl {
    private String host;
	private int port;


    public UserImpl(String host, int port){
        host = host;
        port = port;
	}

    public void signup(String id, String pass){
		
        /*UserMainServer.downloadResponse response = UserMainServer.downloadResponse.newBuilder()
            .setFileContent(server.download(request.getFileId(),request.getCookie())).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();	*/

    }
    public void login(String id, String pass){
		
       /* UserMainServer.downloadResponse response = UserMainServer.downloadResponse.newBuilder()
            .setFileContent(server.download(request.getFileId(),request.getCookie())).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();	*/

    }
    public void logout(String id){
		
        
    }
    /*public void upload(){
		
        UserMainServer.downloadResponse response = UserMainServer.downloadResponse.newBuilder()
            .setFileContent(server.download(request.getFileId(),request.getCookie())).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();	

    }*/
    public void download(String fileID){
		


    }
    












}
