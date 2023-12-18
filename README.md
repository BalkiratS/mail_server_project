# Secure Mail Transfer Protocol with Enhanced Security
This repository includes Python programs for a secure mail transfer protocol (SMTP) with enhanced security features. These enhanced features address vulnerabilities identified in the basic SMTP protocol, specifically data modification attacks.

## Features:

- Secure communication between clients and server using TCP sockets.
- User authentication with username and password stored securely in a JSON file.
- Client and server utilize asymmetric cryptography with public/private key pairs for secure communication.

#### Encryption:
- Symmetric key encryption (ECB mode) for message content using a session key generated dynamically.
- Asymmetric key encryption for initial client authentication and server response.

#### Message Integrity Protection:
- Message Authentication Code (MAC) implemented using a secure hashing algorithm like SHA-256 to ensure message content hasn't been tampered with in transit.

#### Server Concurrency:
- Server handles multiple client connections simultaneously using the fork() function.

#### User Interface:
- Clients and server print informative messages to demonstrate operations and security measures.

### Improved Protocol Description:
1. Client login:
    - Client sends username and password encrypted with server's public key.
    - Server decrypts credentials, verifies against stored user data, and generates a session key.
    - Server sends back encrypted response with login success/failure and the session key (if successful).

2. Message exchange:
    - Client sends encrypted email (including destination users, title, and content) using the session key.
    - Server verifies MAC to ensure message integrity.
    - Server saves received email for each destination user.
    - Server sends encrypted notification to each destination client notifying them of a new message.

3. Reading emails:
    - Client requests inbox list.
    - Server sends encrypted list of received emails with sender, date, and title.
    - Client selects an email by index.
    - Server sends the requested email content encrypted with the session key.
    - Client verifies MAC and displays the decrypted email content.

4. Enhanced Security Features:
    - MAC: The message authentication code adds a layer of data integrity protection, detecting any message modifications during transmission.
    - Asymmetric key encryption: Initial client authentication and server response utilize public/private key pairs for secure key exchange, preventing eavesdropping attacks.

## Usage:
1. Server:
    - Run python3 Server_enhanced.py on the server machine.
    - The server will listen for incoming client connections on port 13000.

2. Client:
    - Run python3 Client_enhanced.py on each client machine.
    - Enter the server IP address and your username/password.
    - Select desired operations from the menu to send/receive/view emails.

## Testing:
- The programs have been tested with multiple client connections and various user actions.
- Deliberate message modifications have been simulated to verify MAC functionality.

## Dependencies:
- Python 3
- Cryptodome library (https://pypi.org/project/pycryptodome/)

## Contribution:
This project was collaboratively developed by Balkirat Padda, Craig Zelmer, Collette Patalinghog, and Mikayla Pichonsky. Contributions were roughly equal for all components.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.
