#TESTED ON PYTHON 2.7.17 WSL

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
import base64
import sys

class RsaEncrypt:
    def __init__(self,pubKeyPath):
        self.pubKeyPath = pubKeyPath

    def __b64enc(self,param):
        return base64.b64encode(param)

    def encryptFile(self,filePath):
        targetFile = self.__b64enc(open(filePath,"rb").read())
        pub = open(self.pubKeyPath,"rb")
        publicKey = RSA.importKey(pub.read())
        cipher = Cipher_PKCS1_v1_5.new(publicKey)
        enc = cipher.encrypt(targetFile)
        with open(os.path.splitext(filePath)[0]+"_enc"+os.path.splitext(filePath)[1], "wb") as fOut:
            fOut.write(self.__b64enc(enc))
    

class RsaDecrypt:
    def __init__(self,pubKeyPath):
        self.pubKeyPath = pubKeyPath
    
    def __b64dec(self,param):
        return base64.b64decode(param)

    def __b64enc(self,param):
        return base64.b64encode(param)

    def decryptFile(self,filePath):
        targetFile = self.__b64dec(open(filePath,"rb").read())
        priv = open(self.pubKeyPath,"rb")
        privateKey = RSA.importKey(priv.read())
        cipher = Cipher_PKCS1_v1_5.new(privateKey)
        dec = self.__b64dec(cipher.decrypt(targetFile, None).decode())
        with open(os.path.splitext(filePath)[0]+"_dec"+os.path.splitext(filePath)[1], "wb") as fOut:
            fOut.write(dec)

    def decryptText(self,text):
        targetFile = self.__b64dec(text)
        priv = open(self.pubKeyPath,"rb")
        privateKey = RSA.importKey(priv.read())
        cipher = Cipher_PKCS1_v1_5.new(privateKey)
        dec = self.__b64dec(cipher.decrypt(targetFile, None).decode())
        print(self.__b64enc(dec))

##main
args = sys.argv
if(len(args)<4):
    print("Wrong syntax ma fren, here is how to use it:")
    print("1. Encrypt: python rsaEncrypt.py enc pubkey targetfile")
    print("2. Decrypt: python rsaEncrypt.py dec privkey targetfile")
if args[1] != "enc" and args[1] !="dec":
    print("Wrong syntax ma fren, here is how to use it:")
    print("1. Encrypt: python rsaEncrypt.py enc pubkey targetfile")
    print("2. Decrypt: python rsaEncrypt.py dec privkey targetfile")

if args[1] == "enc":
    #encrypt
    rsaEncrypt = RsaEncrypt(args[2])
    rsaEncrypt.encryptFile(args[3])

if args[1] == "dec":
    #decrypt
    rsaDecrypt = RsaDecrypt(args[2])
    rsaDecrypt.decryptText(args[3])
