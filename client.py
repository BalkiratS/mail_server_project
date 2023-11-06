# This is adapted from the example from
# "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    Student ID - 3097415

import socket
import sys
import datetime
import os

def uploadFile(clientSocket):
    #Get request for filename from server
    message = clientSocket.recv(2048)
    print(message.decode('ascii'))
    
    #Loop to get valid filename from user
    while 1:
        #Get filename from user
        filename = input()
        
        #Check if file exists and get filesize
        try:
            fIn = open(filename, "rb")
            #To get filesize, file must be in same dir as client.py
            filesize = os.path.getsize(filename)
            fIn.close()
            break
        except:
            print("This file does not exist.\nEnter a valid filename")
        
    #Send formatted messsage of filename and size to server
    message = f"{filename}\n{filesize}"
    clientSocket.send(message.encode('ascii'))
    
    #Get confirmation from server
    message = clientSocket.recv(2048)
    print(message.decode('ascii'))
        
    #Begin upload of file to server
    try:
        fIn = open(filename, "rb")
    except:
        print(f"File: '{filename}' cannot be opened")    
    data = fIn.read()
    while data:
        clientSocket.send(data)
        data = fIn.read()
    fIn.close()
    print("Upload process complete")
    
    
def username(clientSocket):
    #Get username from input, send to server for validation
    username = input()
    message = username.encode('ascii')
    clientSocket.send(message)
    
    #Print message, then if valid return 1, if not return 0
    message = clientSocket.recv(2048)
    message = message.decode('ascii')
    print(message)
    if message == "Incorrect username. Connection terminated.":
        return 0
    else:
        return 1


def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    choice = '1'
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
              
        # Client receives welcome message from the server and print it
        message = clientSocket.recv(2048)
        print(message.decode('ascii'))
        
        #Get username from input, send to server for validation
        valid = username(clientSocket)
        if valid == 0:
            clientSocket.close()
            sys.exit(1)
        
        while choice != '3':
            #Get user choice and send to server, do not accept empty string
            while 1:
                choice = input()
                if choice:
                    break
            message = choice.encode('ascii')
            clientSocket.send(message)
            
            if choice == '1':
                #Get formatted string from server and print metadata
                message = clientSocket.recv(2048)
                print(message.decode('ascii'))
            elif choice == '2':
                uploadFile(clientSocket)

            #Recieve operations from server again
            message = clientSocket.recv(2048)
            print(message.decode('ascii'))     
            
        # Client terminate connection with the server
        clientSocket.close()
        print("connection terminated.")
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
