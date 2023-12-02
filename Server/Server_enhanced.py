# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Authors: Craig Zelmer, Collette Patalinghog, Mikayla Pichonsky, Balkirat Padda
import socket
import sys
import os
import json
import datetime as dt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

def gen_AES_key():
    KeyLen = 256
    sym_key = get_random_bytes(int(KeyLen/8))
    return sym_key

def sendMsg(connectionSocket, sym_cipher, message):
    # Encrypt Message
    message_pad = pad(message.encode('ascii'),16)
    message_enc = sym_cipher.encrypt(message_pad)
    # Send Encrypted message length
    msg_len = str(len(message_enc))
    msg_len_pad = pad(msg_len.encode('ascii'),16)
    msg_len_enc = sym_cipher.encrypt(msg_len_pad)
    connectionSocket.send(msg_len_enc)
    # Recv and decrypt Ready to recv message from Client
    ready_enc = connectionSocket.recv(2048)
    ready_pad = sym_cipher.decrypt(ready_enc)
    ready = unpad(ready_pad,16).decode('ascii')
    # If message == 'OK' continue to sending message, otherwise terminate
    if ready == 'OK':
        connectionSocket.send(message_enc)
    else:
        print("Client not ready to recieve message. Terminating")
        connectionSocket.close()
        sys.exit(0)
    return message_enc #Only adding this in case we need it for some reason

def recvMsg(connectionSocket, sym_cipher):
    # Recv and decrypt message length to recv
    msg_len_enc = connectionSocket.recv(2048)
    msg_len_pad = sym_cipher.decrypt(msg_len_enc)
    msg_len = int(unpad(msg_len_pad,16).decode('ascii'))
    # Send OK to server, ready to Recv message
    message = "OK"
    message_pad = pad(message.encode('ascii'),16)
    message_enc = sym_cipher.encrypt(message_pad)
    connectionSocket.send(message_enc)
    # Recv encrypted message, decrypt and return string of message
    message_enc = connectionSocket.recv(msg_len)
    message_pad = sym_cipher.decrypt(message_enc)
    message = unpad(message_pad,16).decode('ascii')
    return message

def handshake(connectionSocket):
    try:
        f = open('server_private.pem','r')
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
    sym_key = validate_user(connectionSocket, username, password)
    # end of block to validate user

    # receiving the OK message from client before sending menu
    response = connectionSocket.recv(2048)
    cipher = AES.new(sym_key, AES.MODE_ECB)
    response_dec = cipher.decrypt(response)
    response_unpad = unpad(response_dec, 16).decode('ascii')

    # Send AES encrypted secret MAC key to client
    secret_key = b"magicman"
    enc_secret_key = cipher.encrypt(pad(secret_key.encode('ascii'),16))
    connectionSocket.send(enc_secret_key)

    # Recieve Final OK message and move into main function
    response = connectionSocket(2048)
    response_dec = cipher.decrypt(response)
    response_unpad = unpad(response_dec, 16).decode('ascii')

    return cipher, username, secret_key # added a username to return to be used in subprotocols

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

    # create directories for all the known clients
    create_client_dir()
        
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

                # Get sym_key and username from valid login
                sym_cipher, username, secret_key = handshake(connectionSocket) 
                
                # Encrypt with symmetric key and send menu to client
                menu = '\nSelect the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\n'
                sendMsg(connectionSocket, sym_cipher, menu)

                while True:
                    # Receive and decrypt the client user's choice
                    choice = recvMsg(connectionSocket, sym_cipher)
                    if choice == '1':
                        recv_email(connectionSocket, sym_cipher, username)

                    elif choice == '2':
                        display_inbox(connectionSocket, sym_cipher, username)

                    elif choice == '3':
                        display_email(connectionSocket, sym_cipher, username)

                    elif choice == '4':
                        terminate_connection(connectionSocket, username)
                        break

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
        except Exception as e:
            print(f'Unhandled exception of type {type(e).__name__}: {str(e)}')
            serverSocket.close() 
            sys.exit(0)

def validate_user(c, uname, pword):
    # opens the user_pass.json
    f = open('user_pass.json') # Alternative path is Server/user_pass.json OR user_pass.json

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
        sys.exit(0)
    else: # if user is validated
        c.send('Success'.encode('ascii')) # Sent this to parallel the 'invalid username and password' line
        # generate symmetric key
        sym_key = gen_AES_key()
        
        client_pubkey = f'{uname}_public.pem' # Alternative paths if crashing: Clients/{client_num}/{uname}_public.pem OR {uname}_public.pem

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
        enc_msg = cipher.encrypt(sym_key)
        c.send(enc_msg)
        print(f'Connection Accepted and Symmetric Key generated for client: {uname}')

        return sym_key

        
def recv_email(connectionSocket, sym_cipher, username):
    # Receive responses from client.py inputs
    sendMsg(connectionSocket, sym_cipher, "Send the email")

    # recieve destinations
    destination = recvMsg(connectionSocket, sym_cipher)

    # recive title
    title = recvMsg(connectionSocket, sym_cipher)

    # reject the message if the title exceed the 100 char limit
    if len(title) > 100:
        print("Message Rejected: Title too long")
        return
    
    # recive the content lenght
    content_length = int(recvMsg(connectionSocket, sym_cipher))

    # reject the message if the content length is 0 or it exceed the 1000000 char limit
    if content_length > 1000000:
        print("Message Rejected: Content too long")
        return
    
    if content_length == 0:
        print("Message without content")
        return
    
    message = ""
    while True:
        # Receive data from the client in chunks (2048 bytes)
        data = recvMsg(connectionSocket, sym_cipher)

        # Append the data to the message string 
        message += data

        # Check if all expected data has been received
        if len(message) == content_length:
            break

    # Get the current date and time after the whole message is recieved
    date_time = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    email_str = (
        f"From: {username}\n"
        f"To: {destination}\n"
        f"Time and Date: {date_time}\n"
        f"Title: {title}\n"
        f"Content Length: {content_length}\n"
        f"Content: \n{message}"
    )

    email_notif = f'An email from {username} is sent to {destination} has a content length of {content_length}.'

    # print the notification for email sent/received
    print(email_notif)

    # get the list of the destinations
    destination_list = destination.split(';')

    # save the email txt file in all the dest folders and update the json for each folder
    for dest in destination_list:
        file_name = f"{dest}/{username}_{title}.txt"
        with open(file_name, 'w') as file:
            file.write(email_str)
        
        add_entry_to_inbox(dest, username, title, date_time)

    return

def display_inbox(c, sym_cipher, username):
    # path for the client's inbox
    inbox_path = f'{username}/{username}_inbox.json' # alternative path Server/{username}/{username}_inbox.json

    # open and load the json into a dictionary
    f = open(inbox_path)
    inbox_dict = json.load(f)
    f.close()

    # create a json string from the json file and encrypt it with
    # the symmetric key
    inbox = json.dumps(inbox_dict)
    inbox_pad = pad(inbox.encode(), 16)
    inbox_enc = sym_cipher.encrypt(inbox_pad)

    c.sendall(inbox_enc)

    return
    
def display_email(c, sym_cipher, username):
    initial_msg = 'The server request email index'
    sendMsg(c, sym_cipher, initial_msg)

    # Get email index
    index = int(recvMsg(c, sym_cipher))

    # Load inbox json
    inbox_path = f'{username}/{username}_inbox.json' # alternative path Server/{username}/{username}_inbox.json
    f = open(inbox_path)
    inbox_dict = json.load(f)
    f.close()

    # Get title of email from inbox based on index
    for email in inbox_dict['inbox']:
        if email['Index'] == index:
            title = email['Title']

    # Get the name of the source client from the inbox based on index
    for email in inbox_dict['inbox']:
        if email['Index'] == index:
            src = email['From']

    # Access email file
    #file_name = f"{username}/{username}_{title}.txt"
    file_name = f"{username}/{src}_{title}.txt"
    with open(file_name, 'r') as f:
        # Send file size to client
        file_size = str(os.path.getsize(file_name))
        sendMsg(c, sym_cipher, file_size)
        email = f.read()

    # Send and encrypt email to client
    email_enc = sym_cipher.encrypt(pad(email.encode('ascii'), 16))
    c.sendall(email_enc)

    return

def terminate_connection(c, username):
    print(f"Terminating connection with {username}.")
    c.close()
    return


def create_client_dir():

    with open('user_pass.json', 'r') as file:
        user_data = json.load(file)
    
    all_clients = list(user_data.keys())

    for client in all_clients:

        # Get the current working directory
        base_directory = os.getcwd()

        # Construct the full path for the user's directory
        user_directory = os.path.join(base_directory, client)

        # Check if the directory already exists
        if not os.path.exists(user_directory):
            # If it doesn't exist, create the directory
            os.makedirs(user_directory)

            # Create a JSON file in the user's directory
            json_file_path = os.path.join(user_directory, f'{client}_inbox.json')

            # Initialize inbox_data as an empty list
            inbox_data = []

            # Write an empty inbox to the JSON file
            with open(json_file_path, 'w') as json_file:
                json.dump({"inbox": inbox_data}, json_file, indent=2)



def add_entry_to_inbox(client, from_client, title, date_time):
    # Get the current working directory
    base_directory = os.getcwd()

    # Construct the full path for the user's directory
    user_directory = os.path.join(base_directory, client)

    # Check if the directory already exists
    if not os.path.exists(user_directory):
        print(f"Error: Directory does not exist for {client}")
        return

    # Construct the full path for the user's inbox JSON file
    json_file_path = os.path.join(user_directory, f'{client}_inbox.json')

    # Load existing inbox data
    with open(json_file_path, 'r') as json_file:
        inbox_data = json.load(json_file)

    # Create a new entry
    index = len(inbox_data.get("inbox", [])) + 1

    entry = {
        "Index": index,
        "From": from_client,
        "DateTime": date_time,
        "Title": title
    }

    # Add the new entry to the inbox
    inbox_data.setdefault("inbox", []).append(entry)

    # Write the updated inbox data back to the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(inbox_data, json_file, indent=2)
    return

def create_mac(key, message):
    h = HMAC.new(key, msg=message, digestmod=SHA256) # create a new mac for the message
    return h.hexdigest() # return the mac

def verify_mac(key, message, mac):
    h = HMAC.new(key, msg=message, digestmod=SHA256) # create a new mac for the message
    try:
        h.hexverify(mac) # verify if the new mac matches the mac recieved from the other side
        return True
    except ValueError:
        print("This message has been tampered with") # if no match there is a problem
        return False

#-------
server()