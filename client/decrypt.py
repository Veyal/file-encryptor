import sys
sys.path.append("./lib/")
from decryptor import Decryptor
import sys

from time import time
from datetime import datetime

import json
import requests
import platform
import socket
import os
import uuid

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
######################################

if sys.platform == "linux" or sys.platform =="linux2":
    folder = "key/"
else:
    folder = "key\\"

args = sys.argv

if(len(args)<2):
    print("Wrong syntax my friend, let me tell u how to use it:")
    print("python decrypt.py [uid]")
else:
    #Record Start Time
    start = time()
    startTime = datetime.now().time()
    print("Start process on "+ str(startTime))
    print("")

    startDecrypt = time()
    print("Start Decrypting Private Key on " + str(datetime.now().time()))
    if sys.platform == "linux" or sys.platform =="linux2":
        d = Decryptor("lib/config.json")
    else:
        d = Decryptor("lib\\config.json")
    try:
        d.decryptRsaKey(folder+"privkey1_enc.der",args[1])
    except Exception as err:
        raise SystemExit(err)
    size = d.decryptFiles()
    print("End Decrypting Private Key on " + str(datetime.now().time()))
    endDecrypt = time()

    #Record End time
    end = time()
    print("")
    print("End process on "+ str(datetime.now().time()))
    print("")
    print("Total Size : " + str(size) + " bytes")
    print("Decrypting private key time: "+ str(endDecrypt-startDecrypt) + " seconds")
    print("time elapsed: "+ str(end-start) + " seconds")

    #Record Time Duration to file
    with open("time.log", "a") as logFile:
        logFile.write("[DECRYPT] : "+ str(size) +" bytes  | "+ str(end-start) + " seconds\n")

    try:
        config = json.load(open('lib/config.json',"rb"))
        url = config['target_server']+'log'
        body={'type':'decrypt','duration':str(end-start),'size': str(size),'compName':getCompName(),'macAddr': getMacAddress()}
        result = postRequest(url,body)
        print("Send log success")
    except:
        print("Failed to send log")
