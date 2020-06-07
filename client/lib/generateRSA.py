#TESTED ON PYTHON 2.7.17 WSL

from Crypto.PublicKey import RSA

class RsaGenerator:

    def __init__(self,bytes):
        self.key = RSA.generate(bytes)
    
    def generateKey(self,target_private,target_public):
        self.__generatePrivateKey(target_private)
        self.__generatePublicKey(target_public)

    def __generatePrivateKey(self,target_private):
        with(open(target_private,'wb')) as priv:
            priv.write(str(self.key.exportKey('DER')))

    def __generatePublicKey(self,target_public):
        with(open(target_public,'wb')) as pub:
            pub.write(str(self.key.publickey().exportKey('DER')))

# rsaGenerator = RsaGenerator(8192)
# rsaGenerator.generateKey('privatekey8.der','publickey8.der')