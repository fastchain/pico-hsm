import pytest
import hashlib
import os
import binascii
import json
import random
from picohsm import DOPrefixes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, x448
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from picohsm.const import DEFAULT_RETRIES, DEFAULT_DKEK_SHARES
#from const import DEFAULT_DKEK
from picohsm import PicoHSM
from eth_account import Account


from binascii import unhexlify
import secrets

class SecureLock2:
    def __init__(self, picohsm, secretkey=None):
        self.picohsm = picohsm
        #self.secretkey = secrets.token_bytes(32)
        #self.secretkey = bytes([0x1] * 32)
        self.secretkey = secretkey

    def mse(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pn = sk.public_key().public_numbers()
        self.__pb = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

        ret = self.picohsm.send(cla=0x80, command=0x64, p1=0x3A, p2=0x01, data=list(self.__pb))

        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(ret))
        shared_key = sk.exchange(ec.ECDH(), pk)

        xkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12+32,
            salt=None,
            info=self.__pb
        )
        kdf_out = xkdf.derive(shared_key)
        self.__key_enc = kdf_out[12:]
        self.__iv = kdf_out[:12]

    def encrypt_chacha(self, data):
        chacha = ChaCha20Poly1305(self.__key_enc)
        ct = chacha.encrypt(self.__iv, data, self.__pb)
        return ct

    def unlock_device(self):
        ct = self.get_skey()
        self.picohsm.send(cla=0x80, command=0x64, p1=0x3A, p2=0x03, data=list(ct))

    def _get_key_device(self):
        # if (platform.system() == 'Windows' or platform.system() == 'Linux'):
        #     from secure_key import windows as skey
        # elif (platform.system() == 'Darwin'):
        #     from secure_key import macos as skey
        # else:
        #     print('ERROR: platform not supported')
        #     sys.exit(-1)
        # return skey.get_secure_key()
        #return secrets.token_bytes(32)
        return self.secretkey

    def get_skey(self):
        self.mse()
        ct = self.encrypt_chacha(self._get_key_device())
        return ct

    def enable_device_aut(self):
        ct = self.get_skey()
        self.picohsm.send(cla=0x80, command=0x64, p1=0x3A, p2=0x02, data=list(ct))

    def disable_device_aut(self):
        ct = self.get_skey()
        self.picohsm.send(cla=0x80, command=0x64, p1=0x3A, p2=0x04, p3=list(ct))


class Config:
    def __init__(self):
        self.DKEK = secrets.token_bytes(32)
        self.DKEK_SHARES = 1
        self.HSM_ACCESS_KEY = secrets.token_bytes(32)
        self.PIN = ''.join(random.choices('0123456789', k=10))
        self.SOPIN = ''.join(random.choices('0123456789', k=10))
        self.OPTIONS = 0x0001
        self.RETRIES = 3
        #self.ETH_SECRET_KEY = secrets.token_bytes(32)
        self.ETH_SECRET_KEY = secrets.token_bytes(32)
        self.ETH_ADDRESS = Account.from_key("0x" +  binascii.hexlify(self.ETH_SECRET_KEY).decode('utf-8'))
        self.KEY_ID = 0

    def safeConfig(self,configpath):
        config = {
            "PIN": self.PIN,
            "SOPIN": self.SOPIN,
            "ETH_ADDRESS": self.ETH_ADDRESS.address ,
            "HSM_ACCESS_KEY": binascii.hexlify(self.HSM_ACCESS_KEY).decode('utf-8'),
            "KEY_ID":self.KEY_ID,
        }
        print(config)
        with open(configpath, 'w') as file:
            json.dump(config, file, indent=4)

    #def loadConfig(self,configpath):




def InitDevice(configpath):
    if os.path.exists(configpath):
        print("Config exists. Init procedure stopped.")
        return 0
    device = PicoHSM()
    device_config = Config()
    #print(device_config.HSM_ACCESS_KEY)
    device.initialize(pin=device_config.PIN,
                      sopin=device_config.SOPIN,
                      options=device_config.OPTIONS,
                      retries=device_config.RETRIES,
                      dkek_shares=device_config.DKEK_SHARES)

    device.import_dkek(device_config.DKEK)

    slck = SecureLock2(device,device_config.HSM_ACCESS_KEY)
    slck.enable_device_aut()
    slck.unlock_device()
    # try:
    #     slck.enable_device_aut()
    #     slck.unlock_device()
    # except Exception as e:
    #     print(e)
    #     return e



    # private_key =  secrets.token_bytes(32)
    # account = Account.from_key("0x" +  binascii.hexlify(private_key).decode('utf-8'))
    # #print(f"Address: {account.address}")

    curve=ec.SECP256K1
    pkey = ec.derive_private_key(
        int.from_bytes(device_config.ETH_SECRET_KEY, byteorder='big'),
        curve(),  # Curve used in Ethereum
        default_backend()
    )
    device_config.KEY_ID = device.import_key(pkey,dkek=device_config.DKEK)
    # pubkey = device.public_key(keyid, param=curve().name)
    device_config.safeConfig(configpath)
    return device_config

InitDevice("./testDeviceconfig.json")

'''
#generating random DKEK key, so key transfer will be impossible with DKEK transfer
DKEK = secrets.token_bytes(32)
DKEK_SHARES = 1
RETRIES=3
PIN = '648219'
SOPIN = '57621880'
OPTIONS = 0x0001 # Enable or disable RESET RETRY COUNTER command

device = PicoHSM()
device.initialize(pin=PIN, sopin=SOPIN, options=OPTIONS, retries=RETRIES, dkek_shares=1)
slck = SecureLock2(device)
try:
    slck.enable_device_aut()
except:
    print("enabled")
slck.unlock_device()


resp = device.import_dkek(DKEK)


#Generating secret key
private_key =  secrets.token_bytes(32)
account = Account.from_key("0x" +  binascii.hexlify(private_key).decode('utf-8'))

print(f"Address: {account.address}")
curve=ec.SECP256K1
pkey = ec.derive_private_key(
    int.from_bytes(private_key, byteorder='big'),
    curve(),  # Curve used in Ethereum
    default_backend()
)

#print(f"Private Key: {private_key}")

#print(device.get_first_free_id())
#pkey = ec.generate_private_key(curve())
keyid = device.import_key(pkey,dkek=DKEK)
pubkey = device.public_key(keyid, param=curve().name)
#assert(pubkey.public_numbers() == pkey.public_key().public_numbers())
#device.delete_file(DOPrefixes.KEY_PREFIX, keyid)
#device.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)

##pkcs11-tool -l  --id 31  --pin 648219 --type privkey   --set-id 1
#slck.disable_device_aut()
'''