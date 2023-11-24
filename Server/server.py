# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer     ID - 3097415

import socket
import sys
import os
import random
import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP

def gen_AES_key():
    KeyLen = 256
    sym_key = get_random_bytes(int(KeyLen/8))
    # Generate Cyphering Block
    cipher = AES.new(sym_key, AES.MODE_ECB)
    return cipher

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

                # Get decrpytion for login
                try:
                    f = open('server_private.pem','r') # original path is Server/server_private.pem
                    priv_key = RSA.import_key(f.read())
                    f.close()
                    
                except:
                    print("Server Public Key could not be found.")
                    connectionSocket.close
                    sys.exit(1)
                cipher_rsa_dec = PKCS1_OAEP.new(priv_key)

                # block to validate user
                enc_user = connectionSocket.recv(2048)
                username = cipher_rsa_dec.decrypt(enc_user).decode('ascii')
                enc_pass = connectionSocket.recv(2048)
                password = cipher_rsa_dec.decrypt(enc_pass).decode('ascii')
                validate_user(connectionSocket, username, password)
                # end of block to validate user
                
                menu = '\nSelect the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\n'
                connectionSocket.send(menu.encode('ascii')) # encrypt

                while True:
                    choice = (connectionSocket.recv(2048)).decode('ascii')
                    if choice == '1':
                        print("create and send here")
                        create_and_send(connectionSocket)

                    elif choice == '2':
                        print("view inbox here")
                        display_inbox(connectionSocket)

                    elif choice == '3':
                        print("view email here")
                        display_email(connectionSocket)

                    elif choice == '4':
                        break
                        #terminate_connection(connectionSocket) # not finished yet

                    else:
                        continue
                
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
    f = open('user_pass.json') # original path is Server/user_pass.json

    # loads the contents of user_pass.json into a dictionary
    user_data = json.load(f)
    f.close()
    
    # if the username is found in the keys of the dictionary
    if uname in user_data.keys():
        # get the password for the user
        password = user_data[uname]
    else: # if not, we'll set a flag to show that the username is invalid
        password = 'p'
    
    # if the password is incorrect or the username is invalid
    if (password != pword or password == 'p'):
        c.send(('Invalid username or password.\nTerminating.').encode('ascii'))
        print(f'The received client information: {uname} is invalid.\nConnection Terminated.')
        c.close()
    else: # if user is validated
        # generate symmetric key
        sym_key = gen_AES_key()
        
        # this formatting is just for pathing purposes
        client_num = f'Client {uname[6:]}'
        client_pubkey = f'Clients/{client_num}/{uname}_public.pem'

        # will open the client's public key to be used for encryption
        try:
            f_key = open(client_pubkey, 'r')
            pubkey = RSA.import_key(f_key.read())
            f_key.close()
        except:
            print('Client Public Key could not be found.')
            sys.exit(1)
        
        # encrypt the symmetric key using the client's public key and send it
        cipher = PKCS1_OAEP.new(pubkey)
        enc_msg = cipher.encrypt(sym_key.encode('ascii'))
        c.send(enc_msg)
        print(f'Connection Accepted and Symmetric Key generated for client: {uname}')

        
def create_and_send(c):
    return

def display_inbox(c):
    return
    
def display_email(c):
    return

def terminate_connection(c):
    return

#-------
server()