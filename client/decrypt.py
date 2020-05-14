import sys
sys.path.append("./lib/")
from decryptor import Decryptor
import sys

from time import time
from datetime import datetime

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
    d = Decryptor("config.json")
    try:
        d.decryptRsaKey("privkey1_enc.der",args[1])
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
