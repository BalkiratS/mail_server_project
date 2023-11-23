# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    ID - 3097415
import socket
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate Key
KeyLen = 256
try:
    fIn = open("key", "rb")
except:
    print("Could not open file: key")
key = bytes(fIn.read())
fIn.close()
# Generate Cyphering Block
cipher = AES.new(key, AES.MODE_ECB)

def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 12000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # Client receives intro message, asks for user input, then sends name to server
        message = clientSocket.recv(2048)
        message = unpad(cipher.decrypt(message),16).decode('ascii')
        message = input(message)
        ct_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
        clientSocket.send(ct_bytes)
        
        #Begin exam taking loop
        while 1:
            #Begin exam questions loop
            for i in range(4):
                #Client recieves question, asks for answer, sends answer
                message = clientSocket.recv(2048)
                message = unpad(cipher.decrypt(message),16).decode('ascii')
                message = input(message)
                ct_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
                clientSocket.send(ct_bytes)

            #Client recieves score, and if they wish to retake exam
            #If client responds y or Y, retake, otherwise end connection
            message = clientSocket.recv(2048)
            message = unpad(cipher.decrypt(message),16).decode('ascii')
            message = input(message)
            ct_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
            clientSocket.send(ct_bytes)
            if message.lower() != 'y':
                break
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
