# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    ID - 3097415
import socket
import sys
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP, AES

def handshake(clientSocket):
        try:
            f = open('server_public.pem','r') 
            # f = open('Clients/Client 1/server_public.pem','r') #Alternate path without folders
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
        enc_pass = cipher_rsa_en.encrypt(password.encode('ascii'))
        clientSocket.send(enc_pass)

        response = clientSocket.recv(2048).decode('ascii')

        # if the username/password is invalid
        if response == 'Invalid username or password.\nTerminating.':
            print(response)
            clientSocket.close()
            sys.exit(0)

        else: # will receive the sym key from the server, encrypt an OK message
              # with it, and send it to server

            # will get the client's private key to be used for sym key decryption
            client_num = f'Client {username[6:]}'
            client_privkey = f'{username}_private.pem'

            try:
                f_key = open(client_privkey, 'r')
                privkey = RSA.import_key(f_key.read())
                f_key.close()
            except:
                print('Client Private Key could not be found.')
            
            # will create a ciphering block for the client private key, then receive and decrypt the
            # symmetric key
            priv_cipher = PKCS1_OAEP.new(privkey)
            sym_key = clientSocket.recv(2048)
            sym_decrypt = priv_cipher.decrypt(sym_key)

            # will create a ciphering block for the symmetric key, then create and send an OK message
            # to the server using symmetric key encryption
            sym_cipher = AES.new(sym_decrypt, AES.MODE_ECB)
            pad_ok = pad('OK'.encode('ascii'), 16)
            ok_enc = sym_cipher.encrypt(pad_ok)
            clientSocket.send(ok_enc)
            return sym_cipher

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
        sym_cipher = handshake(clientSocket)
        
        # Receive menu and decrypt (used existing cipher block from handshake() for continuity)
        menu_recv = clientSocket.recv(2048)
        menu_dec = sym_cipher.decrypt(menu_recv)
        menu_unpad = unpad(menu_dec, 16).decode('ascii')
        while True:
            print(menu_unpad, end='')
            # Get choice, encrypt with symmetric key, then send to server
            choice = input('choice: ')
            choice_pad = pad(choice.encode('ascii'), 16)
            choice_enc = sym_cipher.encrypt(choice_pad)
            clientSocket.send(choice_enc)

            if choice == '1':
                send_email(clientSocket, sym_cipher)
            
            elif choice == '2':
                #print('inbox displays here')
                inbox_recv = clientSocket.recv(2048)
                inbox_dec = sym_cipher.decrypt(inbox_recv)
                inbox_unpad = unpad(inbox_dec, 16).decode()

                inbox = json.loads(inbox_unpad)
                print('{:<10} {:<10} {:<30} {:<20}'.format('Index', 'From', 'DateTime', 'Title'))

                for message in inbox['inbox']:
                    print("{:<10} {:<10} {:<30} {:<20}".format(message['Index'], message['From'], message['DateTime'], message['Title']))

            elif choice == '3':
                initial_msg = unpad(sym_cipher.decrypt(clientSocket.recv(2048)), 16).decode('ascii')

                if initial_msg == 'The server request email index':
                    # Get index, encrypt and send to server
                    index = 'a'
                    while not index.isdigit(): # Check if index is a number
                        index = input('Enter the email index you wish to view: ')
                    index_enc = sym_cipher.encrypt(pad(index.encode('ascii'), 16))
                    clientSocket.send(index_enc)
                    
                    # Get size of email contents file
                    file_size = clientSocket.recv(2048).decode('ascii')
                    remaining = int(file_size)
                    # Initialize file contents container
                    email_chunks = []

                    # Receive email (while checking if entire file contents have been received)
                    while remaining > 0:
                        email_recv = clientSocket.recv(2048)
                        email_dec = sym_cipher.decrypt(email_recv)
                        email_unpad = unpad(email_dec, 16).decode('ascii')
                        email_chunks.append(email_unpad)
                        remaining -= len(email_recv)

                    print(''.join(email_chunks))

            elif choice == '4':
                print('The connection is terminated with the server.')
                break

            else:
                print('Option does not exist. Try again.')

    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

def send_email(clientSocket, sym_cipher):
    # recive the inital message
    inital_msg = unpad(sym_cipher.decrypt(clientSocket.recv(2048)), 16).decode('ascii')

    if inital_msg == "Send the email":
        # Gather input for email
        destinations = input('\nEnter destinations (separated by ;): ')
        clientSocket.sendall(destinations.encode('ascii'))

        title = input('Enter title: ')
        clientSocket.sendall(title.encode('ascii'))

        # reject the message if the title exceed the 100 char limit
        if len(title) > 100:
            print("Message Rejected: Title too long, max 100 characters allowed")
            return

        add_from_file = input('Would you like to load contents from a file?(Y/N) ')

        if add_from_file.upper() == "Y":
            file_name = input('Enter filename: ')
            content_length = 0

            # Check if the specified file exists
            if os.path.isfile(file_name):
                
                # get number of characters in the file
                with open(file_name, 'r') as file:
                    content = file.read()
                    content_length = len(content)

                # Send the content length to the server
                clientSocket.send(f"{content_length}".encode('ascii'))

                 # reject the message if the content length exceed the 1000000 char limit
                if content_length > 1000000:
                    print("Message Rejected: Content too long, max 1000000 characters allowed")
                    return
                
                # start sending the message
                with open(file_name, 'r') as file:
                    while True:
                        chunk = file.read(2048)  # Read 2048 characters at a time
                        if not chunk:
                            break  # Exit the loop when no more content is left
                        clientSocket.sendall(chunk.encode('ascii'))

            else:
                print("Incorrect File Name")

        else:
            # recieve content from user input
            message = input('Enter message contents: ')
            content_length = len(message)

            # Send the content length to the server
            clientSocket.send(str(content_length).encode('ascii'))
            clientSocket.send("".encode('ascii')) # Needed this line or else length and part of message send together?

            # reject the message if the content length exceed the 1000000 char limit or content with 0 char
            if content_length > 1000000:
                print("Message Rejected: Content too long, max 1000000 characters allowed")
                return
            
            if content_length == 0:
                print("No message entered")
                return

            # send the message to the server
            clientSocket.sendall(message.encode('ascii'))

        print('The message is sent to the server.')



#----------
client()
