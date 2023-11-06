# This is adapted from the example from
# "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 13000
# See the following link for more details about the socket liberary
# (https://docs.python.org/3/library/socket.html)
# Author - Craig Zelmer    Student ID - 3097415

import socket
import sys
import json
import os
import datetime

def downloadFile(connectionSocket):
    #Send request for filename
    message = "Please provide the file name"
    connectionSocket.send(message.encode('ascii'))
    
    #Get string of filename and filesize from client
    message = connectionSocket.recv(2048)
    message = message.decode('ascii')
    filedata = message.split('\n')
    filename = filedata[0]
    filesize = filedata[1]
    
    #Send OK message to client
    message = f"OK {filesize}"
    connectionSocket.send(message.encode('ascii'))
    #convert filesize to int for tracking
    filesize = int(filesize)
    countFilesize = int(filesize)
    
    #Begin download of file
    try:
        fOut =  open(filename, "wb")
    except:
        print(f"Could not open file: {filename}")
    data = connectionSocket.recv(512)
    countFilesize -= 512
    while data:
        if countFilesize <= 0:
            break
        else:
            fOut.write(data)
            data = connectionSocket.recv(512)
            countFilesize -= 512
    fOut.close()
    
    #After download of file complete, read in current Database and add new file
    #to dictionary
    time = str(datetime.datetime.now())
    fDb = open("Database.json", "r")
    data = fDb.read()
    fDb.close()
    newEntry = {filename: {"size": filesize, "time": time}}
    #Check if file was empty
    if data:
        database = json.loads(data)
    else:
        database = {}
    database.update(newEntry)
    newDatabase = json.dumps(database)
    fDb = open("Database.json", "w")
    fDb.write(newDatabase)
    fDb.close()


def readJson(connectionSocket):
    #Reads in JSON file into python dict, then returns formatted message to
    #be sent to client
    fDb = open("Database.json", "r")
    data = fDb.read()
    fDb.close()
    message = f"\n{'Name':<25} {'Size(Bytes)':<25} {'Upload Date and Time':<25}"
    #Check if file was empty
    if data:
        database = json.loads(data)
    else:
        database = {}
        #Send empty header of format string if database empty
        return message
    #Add items from database to formatted string
    for key, value in database.items():
        message += f"\n{key:<25} {value['size']:<25} {value['time']:<25}"
    return message


def userAuth(connectionSocket):
    #Get username from client and validate, return 1. return 0 if not user1
    message = connectionSocket.recv(2048)
    username = message.decode('ascii')
    if username != 'user1':
        #Return 0 to terminate connection
        message = "Incorrect username. Connection terminated.".encode('ascii')
        connectionSocket.send(message)
        return 0
    else:
        return 1
        

def server():
    #Server port
    serverPort = 13000
    choice = '1'
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
    
    #Create Database.json if it does not exist
    try:
        fDb = open("Database.json", "x")
    except:
        pass
        #file already exists
    fDb.close()    
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(1)
        
    while 1:
        try:
            #Loop is for user authentication
            while 1:
                #Server accepts client connection
                connectionSocket, addr = serverSocket.accept()
                #print(addr,'   ',connectionSocket)
                
                introMessage = "Welcome to our system.\nEnter your "\
                               "username".encode('ascii')
                connectionSocket.send(introMessage)
                
                #Get username from client and validate
                valid = userAuth(connectionSocket)
                if valid == 0:
                    connectionSocket.close
                elif valid == 1:
                    break
            
            while choice != '3':
                
                #Send operations
                choicesMessage = "\n\nPlease select the operation\n"\
                    "1)View uploaded files' information\n"\
                    "2)Upload a file\n"\
                    "3)Terminate the connection\nChoice:".encode('ascii')
                connectionSocket.send(choicesMessage)
                
                #Server receives choice
                message = connectionSocket.recv(2048)
                choice = message.decode('ascii')
                
                if choice == '1':
                    message = readJson(connectionSocket)
                    connectionSocket.send(message.encode('ascii'))
                elif choice == '2':
                    downloadFile(connectionSocket)
            
            #Server terminates client connection
            connectionSocket.close()
            print("connectionSocket Closed")
            choice = '1'
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        #except:
            #print('Goodbye')
            #serverSocket.close() 
            #sys.exit(0)
            

#-------
server()
