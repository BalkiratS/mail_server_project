# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Authors: Craig Zelmer, Collette Patalinghog, Mikayla Pichonsky, Balkirat Padda
import socket
import sys
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP, AES

def recvMsg(clientSocket, sym_cipher):
    # Recv and decrypt message length to recv
    msg_len_enc = clientSocket.recv(2048)
    msg_len_pad = sym_cipher.decrypt(msg_len_enc)
    msg_len = int(unpad(msg_len_pad,16).decode('ascii'))
    # Send OK to server, ready to Recv message
    message = "OK"
    message_pad = pad(message.encode('ascii'),16)
    message_enc = sym_cipher.encrypt(message_pad)
    clientSocket.send(message_enc)
    # Recv encrypted message, decrypt and return string of message
    message_enc = clientSocket.recv(msg_len)
    message_pad = sym_cipher.decrypt(message_enc)
    message = unpad(message_pad,16).decode('ascii')
    return message
    
def sendMsg(clientSocket, sym_cipher, message):
    # Encrypt Message
    message_pad = pad(message.encode('ascii'),16)
    message_enc = sym_cipher.encrypt(message_pad)
    # Send Encrypted message length
    msg_len = str(len(message_enc))
    msg_len_pad = pad(msg_len.encode('ascii'),16)
    msg_len_enc = sym_cipher.encrypt(msg_len_pad)
    clientSocket.send(msg_len_enc)
    # Recv and decrypt Ready to recv message from Client
    ready_enc = clientSocket.recv(2048)
    ready_pad = sym_cipher.decrypt(ready_enc)
    ready = unpad(ready_pad,16).decode('ascii')
    # If message == 'OK' continue to sending message, otherwise terminate
    if ready == 'OK':
        clientSocket.send(message_enc)
    else:
        print("Client not ready to recieve message. Terminating")
        clientSocket.close()
        sys.exit(0)
    return message_enc #Only adding this in case we need it for some reason
    
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
        menu = recvMsg(clientSocket, sym_cipher)
        while True:
            print(menu, end='')
            # Get choice, encrypt with symmetric key, then send to server
            choice = input('choice: ')
            sendMsg(clientSocket, sym_cipher, choice)

            if choice == '1':
                send_email(clientSocket, sym_cipher)
            
            elif choice == '2':
                inbox_recv = clientSocket.recv(2048)
                inbox_dec = sym_cipher.decrypt(inbox_recv)
                inbox_unpad = unpad(inbox_dec, 16).decode()

                inbox = json.loads(inbox_unpad)
                print('{:<10} {:<10} {:<30} {:<20}'.format('Index', 'From', 'DateTime', 'Title'))

                # sorts the emails by the DateTime value
                email_sort = sorted(inbox['inbox'], key=lambda x: x['DateTime'])

                for email in email_sort:
                    print("{:<10} {:<10} {:<30} {:<20}".format(email['Index'], email['From'], email['DateTime'], email['Title']))

            elif choice == '3':
                initial_msg = recvMsg(clientSocket, sym_cipher)

                if initial_msg == 'The server request email index':
                    # Get index, encrypt and send to server
                    index = 'a'
                    while not index.isdigit() or int(index) <= 0: # Check if index is a number above zero
                        index = input('Enter the email index you wish to view: ')
                    sendMsg(clientSocket, sym_cipher, index)
                    
                    # Get size of email contents file
                    file_size = recvMsg(clientSocket, sym_cipher)
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
    inital_msg = recvMsg(clientSocket, sym_cipher)

    if inital_msg == "Send the email":
        # Gather input for email
        destinations = input('\nEnter destinations (separated by ;): ')
        sendMsg(clientSocket, sym_cipher, destinations)

        title = input('Enter title: ')
        sendMsg(clientSocket, sym_cipher, title)

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
                sendMsg(clientSocket, sym_cipher, str(content_length))

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
                        sendMsg(clientSocket, sym_cipher, chunk)

            else:
                print("Incorrect File Name")

        else:
            # recieve content from user input
            message = input('Enter message contents: ')
            content_length = len(message)

            # Send the content length to the server
            sendMsg(clientSocket, sym_cipher, str(content_length))

            # reject the message if the content length exceed the 1000000 char limit or content with 0 char
            if content_length > 1000000:
                print("Message Rejected: Content too long, max 1000000 characters allowed")
                return
            
            if content_length == 0:
                print("No message entered")
                return

            # Iterate over the message in chunks of 2048 bytes
            for i in range(0, content_length, 2048):
                chunk = message[i:i+2048]
                # Send the chunk to the server
                sendMsg(clientSocket, sym_cipher, chunk)

        print('The message is sent to the server.')



#----------
client()
