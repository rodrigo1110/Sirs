# Remote document access with ransomware protection

The developed project allows Users to create and edit documents locally, upload them remotely to a MainServer, share them with other Users who can download them to their own machine, edit them and upload them again to a MainServer. The main problem being solved is the access to the remote documents by unauthorized users, which is protected against Ransomware Attacks. 

In this README file we describe the overall solution and, in more depth, the commands the User can execute and their result. We will also present how to install
and test the projetc. The security concerns and implementations are explained in detail in the project report.


## General Information

The User component has a command line interface they can type different commands to execute. When the User componenet is compiled and executed in a terminal,
the User is shown the following message: Type 'help' to see avaliable operations. The help command will show the available operations, at the moment: signup, login and exit.
If the User types "signup" he will be prompted to choose a username and password (which needs to be more than 10 characters long and have at least 1 number and 1 special character). If the User chooses a username already in use, they will be informed and asked to choose another one. If the password isn't strong enough, they will also be asked to choose another one. After a successful signup the User should login, in order to have access to the other operations. This (authenticated) operations are: createFile, editFile, showLocalFiles, showRemoteFiles, download, upload, share, unshare, deleteUser, deleteFile, logout, exit. 

The **createFile** operation asks the User to choose a name for the new file and then creates it, in the "files" directory (in the user directory).

The **editFile** operation asks the User for the name of the file they want to edit. If the user types a non-existing name, a new file is created with that name. After that, the user can type the new file's content.

The **showLocalFiles** operation lists the files present in the User's "files" directory. 

The **showRemoteFiles** operation lists the files the User can download from the MainServer. 

The **download** operation asks the User for name of the file they want to download. If the User has permission to download the file, if a file with the same name already exists, the User is asked if they want to replace the file.

The **upload** operation asks the User for the name of the file they want to upload. If the User has permission to upload the file, it replaces the file content on the MainServer.

The **share** operation asks the User for the name of the file they want to share and the names of the User's they want to share the file with. If there is one of the following erros, the User is warned: the file doesn't exist, the User is not the owner, tries to share the file with himself/herself, tries to share the file with a User who doesn't exist or try to share the file with a User who already has permission.

The **unshare** operation asks the User for the name of the file they want to unshare and the names of the User's they want to unshare the file with. If there is one of the following erros, the User is warned: the file doesn't exist, the User is not the owner, tries to unshare the file with himself/herself, tries to unshare the file with a User who doesn't exist or try to unshare the file with a User who already has permission.

The **deleteFile** operation asks the User for the name of the file they want to delete. If there is one of the following erros, the User is warned: the file doesn't exist or the User is not the owner.

The **deleteUser** operation asks the User for their username and password. If the password is wrong, the User is warned.

The **logout** operation makes this authenticated operations not available. The User has login again if they want to access them.

The **exit** operation is both and authenticated and not-authenticated operation. It exits the program.

The MainServer component receives the User's requests and processes them. All the data the MainServer keeps on its database is also sent to the BackUpServer, so that it can also save it to its database. If an attack were to happend that compromised the MainServer, when the BackUpServer takes de MainServer place in the communication with the client, it will be as up-to-date as the MainServer was.

## Pre-requisites

The following tools should be installed for the project to run properly:

* [Maven] - Build Tool and Dependency Management 3.5.0
* [Java] - Java Development Kit 11 (JDK 11)
* [MySQL] - Database Service - https://downloads.mysql.com/archives/installer/ version 8.0.27

## Getting Started

**Setup MySQL**

You should have a MySQL databse running on port 3306, on localhost, with the credentials:

    username = root
    password = root

Instead you can change the credentials in the file databaseAccess.java, in the server\src\main\java\pt\tecnico\grpc\server directory. Change username (line 8) and password (line 9) to your own.

If you are deploying both the MainServer and BackUpServer on the same machine, the name of the database must be different for both. The name of the databse you previously created is passed as an input (either through the terminal or the pom file). If you are deploying them on different machines, both databases can have the same name. If the tables "users", "files" and "permissions" (necessary for the code execution) already exist in the database, they will not be created, so you can execute the Servers with either no tables on the database (they will be created) or with **all** tables created.

## How to run

**Install User-MainServer_Contract**

On the terminal, in the directory Sirs_22\User-MainServer_Contract, run:
    
    mvn clean install 

**Install Main-BackupServer_Contract**

On the terminal, in the directory Sirs_22\Main-BackupServer_Contract, run:
    
    mvn clean install 

**How to run the MainServer**

The input arguments can be configured in the pom file or passed through the terminal. The BackUpServer must already be running when the MainServer is executed.

To run through the terminal, in the directory Sirs_22\server:
    
    mvn clean compile exec:java -Dexec.args="databaseName 1" 

To configure the pom file:

    Change line 22: <dbName>rda</dbName> replacing rda with the correct databaseName.

**How to run the BackUpServer**

To run through the terminal, in the directory Sirs_22\server:

    mvn clean compile exec:java -Dexec.args="databaseName 2" 

To configure the pom file:

    Change line 22: <dbName>rda</dbName> replacing rda with the correct databaseName. If MainServer and BackUpServer are running on the same machine, database name's must be different.

	Change line 23:	<instance>1</instance> replacing 1 with 2.

**How to run the User**

To run through the terminal, in the directory Sirs_22\user:

    mvn clean compile exec:java -Dexec.args="MainServerIP BackUpServerIP" 

To configure the pom file:

    Change line 22:	<server.host>localhost</server.host> replacing localhost with the correct MainServer IP.

    Change line 23:	<backupServer.host>localhost</backupServer.host> replacing localhost with the correct BackUpServer IP.


## Demo

Give a tour of the best features of the application.
Add screenshots when relevant.

### Authors

* **Rodrigo Gomes**
* **Catarina Beirolas**
* **Eduardo Noronha**

