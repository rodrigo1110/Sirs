package pt.tecnico.grpc.server;

import java.sql.*;

public class databaseAccess {

    private String dbhost = "";
	private static String username = "root";
	private static String password = "root";
    private String databaseName = "root";
    private static Connection connection; 

    public databaseAccess(String databaseName){
		this.databaseName = databaseName;
        this.dbhost = "jdbc:mysql://localhost:3306/" + databaseName;
	}

    public Connection connect(){

/*         System.out.println("Loading driver...");

        try {
            Class.forName("com.mysql.jdbc.Driver");
            System.out.println("Driver loaded!");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Cannot find the driver in the classpath!", e);
        } */

        System.out.println("Connecting to the database...");

        try {
            connection = DriverManager.getConnection(dbhost, username, password);
            System.out.println("Database connected!");
            
            Statement stmt = connection.createStatement();

            // para criar table users --- se isto resultar, verificar se existe, se nao, criar
            String sql = "CREATE TABLE users " +
            "(username VARCHAR(45) not NULL, " +
            " password VARCHAR(80) not NULL, " + 
            " cookie VARCHAR(80), " + 
            " salt BLOB not NULL, " + 
            " publickey BLOB not NULL, " + 
            " hash BLOB not NULL, " + 
            " PRIMARY KEY ( username ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table users in database..."); 
            
            /////////

            sql = "ALTER TABLE users CHANGE COLUMN username username VARCHAR(45) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL";
            stmt.executeUpdate(sql);
            System.out.println("Table users altered...");   

            /////////	  
             

             //para criar table files --- se isto resultar, verificar se existe, se nao, criar
            sql = "CREATE TABLE files " +
            "(filename VARCHAR(45) not NULL, " +
            " filecontent BLOB not NULL, " + 
            " fileowner VARCHAR(45) not NULL, " +
            " hash BLOB not NULL, " + 
            " PRIMARY KEY ( filename ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table files in database...");   	
            
            /////////

            sql = "ALTER TABLE files CHANGE COLUMN filename filename VARCHAR(45) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL";
            stmt.executeUpdate(sql);
            System.out.println("Table files altered...");   

            /////////	
            

            // para criar table permissions --- se isto resultar, verificar se existe, se nao, criar
            sql = "CREATE TABLE permissions " +
            "(filename VARCHAR(45) not NULL, " +
            " username VARCHAR(45) not NULL, " +
            " symmetrickey BLOB not NULL, " + 
            " initializationvector BLOB not NULL, " + 
            " hash BLOB not NULL, " +  
            " PRIMARY KEY ( filename, username ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table permissions in database...");    	 
            
            /////////

            sql = "ALTER TABLE permissions CHANGE COLUMN filename filename VARCHAR(45) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL";
            stmt.executeUpdate(sql);
            System.out.println("Table permissions altered...");   

            sql = "ALTER TABLE permissions CHANGE COLUMN username username VARCHAR(45) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL";
            stmt.executeUpdate(sql);
            System.out.println("Table permissions altered...");   

            /////////
            

            ResultSet rs = stmt.executeQuery("select * from users");

            while (rs.next()) {
				String userName = rs.getString("username");
                String password = rs.getString("password");
				String cookie = rs.getString("cookie");

				System.out.println(userName + password + cookie + " now has an account.\n");
			} 

        } catch (SQLException e) {
            System.out.println(e);
            if(e.getClass().toString().compareTo("class java.sql.SQLSyntaxErrorException") == 0){
                System.out.println("Tables were not created. They already existed.");
            }
            else{
                throw new IllegalStateException("Cannot connect the database!", e);
            }
        } 
         

        return connection;
    }


    
}