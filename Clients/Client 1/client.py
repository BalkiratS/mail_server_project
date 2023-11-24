# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer    ID - 3097415
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP, AES

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
            f = open('Clients/Client 1/server_public.pem','r') # Alternative path: Clients/Client 1/server_public.pem - may need to remove folders preceding name
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

        else: # will receive the sym key from the server, encrypt an OK message
              # with it, and send it to server

            # will get the client's private key to be used for sym key decryption
            client_num = f'Client {username[6:]}'
            client_privkey = f'Clients/{client_num}/{username}_private.pem'

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
        
        #clientSocket.send(enc_user)
        #clientSocket.send(enc_pass)
        
        menu = clientSocket.recv(2048).decode('ascii')
        while True:
            print(menu, end='')
            choice = input('choice: ')
            clientSocket.send(choice.encode('ascii'))

            if choice == '1':
                destinations = input('Enter destinations (separated by ;): ')
                clientSocket.send(destinations.encode('ascii'))

                title = input('Enter title: ')
                clientSocket.send(title.encode('ascii'))

                add_from_file = input('Would you like to load contents from a file?(Y/N) ')
                clientSocket.send(add_from_file.encode('ascii'))

                if add_from_file == "Y" or add_from_file == "y":
                    message = input('Enter filename: ')
                else:
                    message = input('Enter message contents: ')
                clientSocket.send(message.encode('ascii'))

                print('The message is sent to the server.')
            
            elif choice == '2':
                print('inbox displays here')

            elif choice == '3':
                initial_msg = clientSocket.recv(2048).decode('ascii')

                index = input('Enter the email index you wish to view: ')
                clientSocket.send(index.encode('ascii'))

            elif choice == '4':
                print('The connection is terminated with the server.')
                break

            else:
                print('Option does not exist. Try again.')

    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
