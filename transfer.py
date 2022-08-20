#I want to create a script that allows me to send files from on system to the other

#Useful libraries that I would be working with -->
import socket
import ip_info
import os
import pickle
import tqdm
import traceback
import shinigami_crypter as sgc


#Declaring the various classes that would handle the sending and receiving of file via socket
class Transfer:
    def __init__(self, attacker = None, target = None):
        self.crypter = sgc.Crypter()
        self.s = socket.socket()
        self.user, self.host, self.publicIP, self.privateIP = ip_info.main()
        self.bufferSize = 4096
        self.separator = "<separator>"
        self.port = 5055
        self.attacker = attacker
        self.target = target

    #This handles the sender side
    def sender(self, host, filename):
        try:
            filePath = f"{os.getcwd()}\\{filename}"
            if os.path.exists(filePath):
                filePath = filePath
            elif os.path.exists(filename):
                filePath = filename
            else:
                raise FileNotFoundError("Declare file path correctly")
            
            filesize = os.path.getsize(filePath)

            print(f"Connecting to {host}: {self.port}")
            self.s.connect((host, self.port))
            print("Connected")

            file_, fernetKey, stat = self.crypter.encrypter(filePath) #Encrypting the file before sending it
            print(f"Sender FernetKey: {fernetKey}")
            #Sending the file name and file path
            #fernetKey = "testing"
            packet = pickle.dumps([filePath, filesize, fernetKey])
            #self.s.send(f"{filePath}{self.separator}{filesize}{self.separator}{fernetKey}".encode())
            self.s.send(packet)
            print(f"File Data: {filePath}{self.separator}{filesize}")
            progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(filePath, "rb") as f:
                while True:
                    # read the bytes from the file
                    bytes_read = f.read(self.bufferSize)
                    if not bytes_read:
                        # file transmitting is done
                        break
                    # we use sendall to assure transimission in 
                    # busy networks
                    self.s.sendall(bytes_read)
                    # update the progress bar
                    progress.update(len(bytes_read))
            # close the socket
            self.s.close() 
            _file_, stat_ = self.crypter.decrypter(filePath, fernetKey) #Decrypting the file after sending it
        except Exception as e:
            stat_ = f"An error when trying to set up connection with sender due to [{e}]"
            print(stat_)
            traceback.print_exc()
            raise KeyboardInterrupt
        return stat_

    #This handles the receiver side
    def receiver(self, host):
        try:
            print(f"Host: {host}.. Port: {self.port}")
            self.s.bind((host, self.port))
            self.s.listen(5)
            print(f"Listening on {host}: {self.port}")

            client_socket, addr = self.s.accept()
            print(f"{addr} is connected successfully!")

            #Receiving the filename and filesize
            #recv = client_socket.recv(self.bufferSize).decode()
            recv = client_socket.recv(self.bufferSize)
            packet = pickle.loads(recv)
            #filename, fileSize, fernetKey = recv.split(self.separator)
            filename, fileSize, fernetKey = packet[0], packet[1], packet[2]
            #print(recv.split(self.separator))
            print(f"Receiver FernetKey: {fernetKey}, Type: {type(fernetKey)}")
            print(f"Receiver Filename: {filename}")
            print(f"Receiver File size: {fileSize}")
            filename = os.path.basename(filename)
            fileSize = int(fileSize)

            #Now its time to receive the file
            progress = tqdm.tqdm(range(fileSize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
            with open(filename, "wb") as f:
                while True:
                    # read 1024 bytes from the socket (receive)
                    bytes_read = client_socket.recv(self.bufferSize)
                    if not bytes_read:    
                        # nothing is received
                        # file transmitting is done
                        break
                    # write to the file the bytes we just received
                    f.write(bytes_read)
                    # update the progress bar
                    progress.update(len(bytes_read))
            # close the client socket
            client_socket.close()
            # close the server socket
            self.s.close()
            filePath = os.path.basename(filename)

            _file_, stat_ = self.crypter.decrypter(filename, fernetKey) #Decrypting the file
        except Exception as e:
            stat_ = f"An error occured when setting up connection with receiver due to [{e}]"
            print(stat_)
            traceback.print_exc()
            raise KeyboardInterrupt
        return filename, stat_



if __name__ == "__main__":
    print("FILE DOWNLOADER \n")

    #send = emailer("switch.py")
    #print(send)
    #a = Transfer().sender("192.168.144.1", "switcher.py")
    a = Transfer().receiver()

    print("\nExecuted sucessfully!!")