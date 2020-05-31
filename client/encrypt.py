import sys
sys.path.append("./lib/")
from encryptor import Encryptor

from time import time
from datetime import datetime

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
