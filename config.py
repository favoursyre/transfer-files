#These class would handle the fetching of either private or public keys
class GetKey:
    def __init__(self):
        pass

    #This function gets the akatsuki public key
    def publicKey(self):
        keyPath = "publicKey.pem"
        with open(keyPath, "r") as publicK:
            key = publicK.read()
            #print(f"Public Key: {key}")
        return key

    #This function gets the akatsuki private key
    def privateKey(self):
        keyPath = "privateKey.pem"
        with open(keyPath, "r") as privateK:
            key = privateK.read()
            #print(f"Private Key: {key}")
        return key