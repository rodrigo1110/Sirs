package pt.tecnico.grpc.server;

import java.sql.*;

public class databaseAccess {

    private static String dbhost = "jdbc:mysql://localhost:3306/sirs";
	private static String username = "root";
	private static String password = "root";
    private static Connection connection; 

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

            /* para criar table users --- se isto resultar, verificar se existe, se nao, criar
            String sql = "CREATE TABLE users " +
            "(username VARCHAR(45) not NULL, " +
            " password VARCHAR(45) not NULL, " + 
            " cookie VARCHAR(45), " + 
            " PRIMARY KEY ( username ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table users in database...");   	  
            */

            /* para criar table files --- se isto resultar, verificar se existe, se nao, criar
            String sql = "CREATE TABLE files " +
            "(filename VARCHAR(45) not NULL, " +
            " filecontent LONGTEXT not NULL, " + 
            " fileowner VARCHAR(45) not NULL, " + 
            " PRIMARY KEY ( filename ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table files in database...");   	  
            */

            /* para criar table permissions --- se isto resultar, verificar se existe, se nao, criar
            String sql = "CREATE TABLE permissions " +
            "(filename VARCHAR(45) not NULL, " +
            " username VARCHAR(45) not NULL, " + 
            " PRIMARY KEY ( filename, username ))"; 

            stmt.executeUpdate(sql);

            System.out.println("Created table permissions in database...");   	  
            */

            ResultSet rs = stmt.executeQuery("select * from users");

            while (rs.next()) {
				String userName = rs.getString("username");
                String password = rs.getString("password");
				String cookie = rs.getString("cookie");

				System.out.println(userName + password + cookie + " now has an account.\n");
			} 

        } catch (SQLException e) {
            throw new IllegalStateException("Cannot connect the database!", e);
        }

        return connection;
    }

    //-------------------- code to be shared between main and backup server for access to db -----------------

}