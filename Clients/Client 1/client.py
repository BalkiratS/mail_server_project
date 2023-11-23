# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    ID - 3097415
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # Client is asked for username and password
        # Encrypt with server public key. Send to server
        username = input('Enter your username: ')
        clientSocket.send(username.encode('ascii'))
        password = input('Enter your password: ')
        clientSocket.send(password.encode('ascii'))

        response = clientSocket.recv(2048).decode('ascii')
        if response == 'Invalid username or password.\nTerminating.':
            print(response)
            clientSocket.close()

        else:
            print('yay')
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
