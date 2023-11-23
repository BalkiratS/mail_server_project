# This is adapted from "Computer Networking: A Top Down Approach" textbook chapter 2
# Author - Craig Zelmer     ID - 3097415

import socket
import sys
import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate Key
KeyLen = 256
sym_key = get_random_bytes(int(KeyLen/8))
# Generate Cyphering Block
cipher = AES.new(sym_key, AES.MODE_ECB)

#Format "Number1 operator Number2 =" ops:{+, -, *} Num={0,100}
def gen_question():
    op_list = ['+', '-', '*']
    num1 = random.randint(0, 100)
    num2 = random.randint(0, 100)
    op_rand = random.randint(0, 2)
    op = op_list[op_rand]
    question = f"{num1} {op} {num2} = "
    return question

#Gets answer from question generated in gen_question
def get_answer(question):
    qList = question.split()
    if qList[1] == '+':
        return int(qList[0]) + int(qList[2])
    if qList[1] == '-':
        return int(qList[0]) - int(qList[2])
    if qList[1] == '*':
        return int(qList[0]) * int(qList[2])

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
                
                #Server connects. No other actions. Disconnect when recieving any message form client
                message = connectionSocket.recv(2048)
                print("Disconnecting.")
                
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
            
        
#-------
server()
