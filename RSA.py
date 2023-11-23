from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

# Generate private and public keys
key = RSA.generate(2048)
private_key = key.export_key()
print(private_key)

public_key = key.publickey().export_key()
print(public_key)

# Get the message to be encrypted
message = input('Enter a message: ')

# Encryption
pubkey = RSA.import_key(public_key)
cipher_rsa_en = PKCS1_OAEP.new(pubkey)
enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
print(enc_data)

# Decryption
privkey = RSA.import_key(private_key)
cipher_rsa_dec = PKCS1_OAEP.new(privkey)
dec_data = cipher_rsa_dec.decrypt(enc_data)
print(dec_data.decode('ascii'))