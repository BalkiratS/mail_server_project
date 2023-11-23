from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

# Generate private and public keys
key = RSA.generate(2048)
private_key = key.export_key('PEM')
f = open('server_private.pem','wb')
f.write(private_key)
f.close()
print(private_key)

public_key = key.publickey().export_key()
f = open('server_public.pem','wb')
f.write(public_key)
f.close()
print(public_key)