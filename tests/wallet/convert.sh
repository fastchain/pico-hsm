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
def get_address(public_key_hex):
    # Convert the public key hex string to a public key object
     # Convert the public key hex string to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Create a PublicKey object using eth_keys
    public_key = KeyAPI.PublicKey(public_key_bytes)

    addr = keccak(public_key_bytes)[-20:]
    return binascii.hexlify(addr)

with open("testdata/1pub.eth", 'r') as binary_file:
        public_key_hex = binary_file.read()


print(get_address(public_key_hex))