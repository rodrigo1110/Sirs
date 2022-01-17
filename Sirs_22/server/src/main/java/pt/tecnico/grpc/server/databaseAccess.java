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
            ResultSet rs = stmt.executeQuery("select * from users");

            while (rs.next()) {
				String userName = rs.getString("username");
				System.out.println(userName + " now has an account.\n");
			} 

        } catch (SQLException e) {
            throw new IllegalStateException("Cannot connect the database!", e);
        }

        return connection;
    }

    //-------------------- code to be shared between main and backup server for access to db -----------------

}