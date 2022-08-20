#I want to create the Private and Public keys that will be used to encrypt/decrypt a file or system

#Useful libraries that I would be working with -->
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import base64
import time
import os

#Defining the function that generates RSA Encryption + Decryption keys / Public + Private keys
def key():
    key = RSA.generate(2048)

    #Generating the private key
    privateKey = key.export_key()
    with open(f'{os.getcwd()}\\privateKey.pem', 'wb') as f:
        f.write(privateKey)
    #print(f"Private Key: {privateKey}")
    time.sleep(1)

    #Generating the public key
    publicKey = key.publickey().export_key()
    with open(f'{os.getcwd()}\\publicKey.pem', 'wb') as f:
        f.write(publicKey)
    #print(f"Public Key: {publicKey}")
    
    return privateKey, publicKey
    


if __name__ == "__main__":
    #Commencing the code -->
    print("SHINIGAMI PRIVATE & PUBLIC KEY \n")

    key()

    print("\nShinigami Private and Public key generated successfully!")

