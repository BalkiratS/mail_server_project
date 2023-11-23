# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    ID - 3097415
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def client():
    # Server Information
    # serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    serverName = input("Enter the server IP or name: ")

    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # Client is asked for username and password
        # Encrypt with server public key. Send to server
        try:
            f = open('Clients/Client 1/server_public.pem','r')
            server_pubkey = RSA.import_key(f.read())
            f.close()
        except:
            print("Server Public Key could not be found.")
            clientSocket.close
            sys.exit(1)
        cipher_rsa_en = PKCS1_OAEP.new(server_pubkey)
        username = input('Enter your username: ')
        enc_user = cipher_rsa_en.encrypt(username.encode('ascii'))
        clientSocket.send(enc_user)
        password = input('Enter your password: ')
        enc_pass = cipher_rsa_en.encrypt(password)
        clientSocket.send(enc_pass)

        response = clientSocket.recv(2048).decode('ascii')
        if response == 'Invalid username or password.\nTerminating.':
            print(response)
            clientSocket.close()

        else:
            print('yay')
        
        clientSocket.send(enc_user)
        clientSocket.send(enc_pass)
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
