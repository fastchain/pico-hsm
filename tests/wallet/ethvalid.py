from eth_account import Account
from eth_utils import keccak
import binascii

#from sha3 import keccak_256

from web3 import Web3
from hexbytes import HexBytes
from eth_account.messages import encode_defunct

from eth_account import Account
from eth_keys import KeyAPI
from eth_utils import keccak
from web3 import Web3
import ecdsa
from eth_utils import keccak
from ecdsa.util import sigdecode_der
import binascii
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der
import hashlib
from eth_account.messages import (
    SignableMessage,
    _hash_eip191_message,
    encode_typed_data,
    encode_defunct
)


def binary_to_hex(data):
    # Read binary data from the file

    # Convert binary data to hexadecimal string
    hex_string = binascii.hexlify(data).decode('utf-8')

    return hex_string

class NoHash:
    def __init__(self, data):
        self._data = data
        self.name = "None"

    def digest(self):
        return self._data

def no_hash(data):
    return NoHash(data)

def bytes_to_int(byte_sequence):
    return int.from_bytes(byte_sequence, byteorder='big')


def validate_signature(public_key_hex, message, signature_hex):
    # Convert the public key hex string to a public key object
     # Convert the public key hex string to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Create a PublicKey object using eth_keys
    public_key = KeyAPI.PublicKey(public_key_bytes)

    addr = keccak(public_key_bytes)[-20:]

   # print('private_key:', private_key.hex())
    print('eth addr: 0x' + addr.hex())

    message=encode_defunct(message)

    #message_hash = keccak(message)
    # Hash the binary message
    #message_hash = message

    w3 = Web3(Web3.HTTPProvider(""))
    # Verify the signature
    #recovered_address = Account.recover_message(message_hash, signature=signature_hex)
    #recovered_address

    recovered_address = w3.eth.account.recover_message(message,signature=HexBytes(signature_hex))
    print(recovered_address)

    # Validate the recovered address matches the address derived from the public key
    #s_valid = recovered_address.lower() == public_key.address.lower()

    return 1

# Example public key, message, and signature (replace these with your actual values)
#public_key_hex = 'fdef26ea6a86575b4d1b643bfd84a5bd573394467bc09380f20e57ca1ee9261dad0c12c208d51bda778e5accbb82533928b0bb77c0ac9ed34ba76ef39a8cfd7e'  # Public key in hex format

def recover_address(message, signature,rec_id):
    w3 = Web3(Web3.HTTPProvider(""))
    message_encoded = encode_defunct(message)
    if rec_id ==0:
        signature+= b'\x1b'
    else:
        signature+= b'\x1c'
    recovered_address = w3.eth.account.recover_message(message_encoded,signature=signature)

    return recovered_address


def get_recovery_id(message, signature, public_key_bytes):
    # Convert the public key hex string to bytes
    #public_key_bytes = bytes.fromhex(public_key_hex)

    # Create a PublicKey object using ecdsa
    #verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes[1:], curve=ecdsa.SECP256k1)
    verifying_key = ecdsa.VerifyingKey.from_der(public_key_bytes,hashfunc=no_hash)
    # Hash the message


    message_encoded = encode_defunct(message)
    message_hash = _hash_eip191_message(message_encoded)
    #message_hash = keccak(message)

    #
    # Assuming the signature is 64 bytes long (32 bytes for r and 32 bytes for s)
    assert len(signature) == 64, "Signature length should be 64 bytes"

    # Split the signature into r and s components
    r = bytes_to_int(signature[:32])
    s = bytes_to_int(signature[32:])
    signature_der = sigencode_der(r, s, ecdsa.SECP256k1.order,)

    # Decode the DER signature
    r, s = ecdsa.util.sigdecode_der(signature_der, ecdsa.SECP256k1.order,)

    # Calculate the recovery ID
    recovery_id = None
    for rec_id in range(4):
        try:
            rec_pub_key = ecdsa.VerifyingKey.from_public_key_recovery(
                signature=signature_der,
                data=message_hash,
                curve=SECP256k1,
                hashfunc=no_hash,
                sigdecode=sigdecode_der,
                #recovery_param=recovery_id
                )
            #print(binary_to_hex(rec_pub_key[rec_id].to_string()))
            #print(binary_to_hex(rec_pub_key[1].to_string()))
            #print(binary_to_hex(verifying_key.to_string()))
            if binary_to_hex(rec_pub_key[rec_id].to_string()) == binary_to_hex(verifying_key.to_string()):
                recovery_id = rec_id
                break
        except ecdsa.BadSignatureError:
            continue

    if recovery_id is None:
        raise ValueError("Could not find the correct recovery ID.")

    return r, s, recovery_id

# with open("1.eth", 'rb') as binary_file:
#         public_key_hex = binary_file.read()
#

with open("./testdata/msg", 'rb') as binary_file:
        message = binary_file.read()

with open('./testdata/signature.der', 'rb') as binary_file:
    signature = binary_file.read()

with open('./testdata/1pub.der', 'rb') as binary_file:
    public_key_bytes = binary_file.read()
#public_key_bytes = open("1pub.der", "rb").read()
#public_key_hex = '04c9ea93d9b871e74a1b7a4d128f845ec0a6352ef244097ce69133fd38d065fe8bda538b4f274aa900af0940a671bffc48f4c859097e46fc6bf8ed02b7abb5c392'

r, s, recovery_id = get_recovery_id(message, signature, public_key_bytes)

print("RECOVERED ADDRESS: "+ recover_address(message, signature,recovery_id), "REC_ID: ",recovery_id)
