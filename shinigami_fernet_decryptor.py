#I want to create a script that would be used for decrypting an encrypted fernet key

#Useful libraries that I would be working -->
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import config


#Declaring the function that would handle the decryption of the fernet key
def decrypt_(fernetKey, privateKey, write = False, target = None):
    if os.path.isfile(fernetKey) == True or os.path.isdir(fernetKey) == True:
        with open(fernetKey, 'rb') as f:
            print("Fernet key found")
            enc_fernet_key = f.read()
    else:
        enc_fernet_key = fernetKey
    #print(enc_fernet_key)

    # Private RSA key
    if os.path.isfile(privateKey) == True:
        private_key = RSA.import_key(open(privateKey).read())
    else:
        private_key = RSA.import_key(privateKey)

    # Private decrypter
    private_crypter = PKCS1_OAEP.new(private_key)

    # Decrypted session key
    dec_fernet_key = private_crypter.decrypt(enc_fernet_key)
    if write and target:
        with open(f'{target}_decryptionKey.txt', 'wb') as f:
            f.write(dec_fernet_key)
    else:
        pass

    #print(f'Private key: {private_key}')
    #print(f'> Decrypted fernet key: {dec_fernet_key}')
    print('> Decryption Completed')
    return dec_fernet_key

#This gets the user input for the various neccessary parameters
def user():
    attacker = input("Enter name of attacker: ")
    fernetKey = input("Enter Encrypted fernet key file name: ")
    write = input("Write status? (True/False) ")
    target = input("Enter name of target: ")
    return attacker, fernetKey, write, target

if __name__ == "__main__":
    #Commencing the code -->
    print("SHINIGAMI FERNET KEY DECRYPTOR \n")

    privateKey = config.GetKey().privateKey()

    print("\nShinigami Fernet Key Decryptor generated successfully!!")
