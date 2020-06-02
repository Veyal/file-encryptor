import sys
sys.path.append("./lib/")
from encryptor import Encryptor

from time import time
from datetime import datetime

import json
import requests

def postRequest(url,body):
    try:
        r = requests.post(url,json=body)
        r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)
    return r
######################################

folder = "key/"

#Record Start Time
start = time()
print("Start process on "+ str(datetime.now().time()))

e = Encryptor("lib/config.json")
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
    body={'type':'encrypt','duration':str(end-start),'size': str(size)}
    result = postRequest(url,body)
    print("Send log success")
except:
    print("Failed to send log")
