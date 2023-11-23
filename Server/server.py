# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer     ID - 3097415

import socket
import sys
import os
import random
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def gen_AES_key():
    KeyLen = 256
    sym_key = get_random_bytes(int(KeyLen/8))
    # Generate Cyphering Block
    cypher = AES.new(sym_key, AES.MODE_ECB)

def server():
    #Server port
    serverPort = 13000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()
            
            # If it is a client process
            if  pid == 0:
                
                serverSocket.close()

                # block to validate user
                username = connectionSocket.recv(2048).decode('ascii')
                password = connectionSocket.recv(2048).decode('ascii')
                validate_user(connectionSocket, username, password)
                # end of block to validate user
                
                connectionSocket.close()
                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except:
            print('Goodbye')
            serverSocket.close() 
            sys.exit(0)

def validate_user(c, uname, pword):
    # opens the user_pass.json
    f = open('Server/user_pass.json')

    # loads the contents of user_pass.json into a dictionary
    user_data = json.load(f)

    # if the username is found in the keys of the dictionary
    if uname in user_data.keys():
        # get the password for the user
        password = user_data[uname]
    else: # if not, we'll set a flag to show that the username is invalid
        password = 'p'
    
    # if the password is incorrect or the username is invalid
    if (password != pword or password == 'p'):
        c.send(('Invalid username or password.\nTerminating.').encode('ascii'))

#-------
server()