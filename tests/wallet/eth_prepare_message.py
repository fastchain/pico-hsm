from asn1crypto.algos import DSASignature
from asn1crypto.core import Integer
from web3 import Web3
import binascii

from hexbytes import HexBytes
from eth_utils import keccak
from eth_account import Account
from eth_account.messages import (
    SignableMessage,
    _hash_eip191_message,
    encode_typed_data,
    encode_defunct
)

from eth_account._utils.signing import (
    hash_of_signed_transaction,
    sign_message_hash,
    sign_transaction_dict,
    to_standard_signature_bytes,
    to_standard_v,
)

from eth_account._utils.signing import (
    hash_of_signed_transaction,
    sign_message_hash,
    sign_transaction_dict,
    to_standard_signature_bytes,
    to_standard_v,
)


def decimal_to_hex(decimal_number):
    # Convert decimal number to hexadecimal
    hex_number = hex(decimal_number)
    # Remove the '0x' prefix
    hex_number = hex_number[2:]
    return hex_number

def sign_message(private_key, message):
    # Create an account object from the private key
    account = Account.from_key(private_key)

    # Encode the message for signing
    # https://github.com/ethereum/eth-account/blob/35ee40604e79dceee5cc61718778e7fb18cf22df/eth_account/messages.py#L116
    message_encoded = encode_defunct(text=message)

    # Create hash to sign
    # https://github.com/ethereum/eth-account/blob/35ee40604e79dceee5cc61718778e7fb18cf22df/eth_account/messages.py#L60
    hash_to_sign = _hash_eip191_message(message_encoded)
    print(f"Hash to sign: {hash_to_sign.hex()}")
    print(f"Signer's address: {account.address}")
    print(f"Signer's address text: {keccak(account._key_obj.public_key.to_bytes())[-20:].hex()}")
    print(f"Public Key: {account._key_obj.public_key.to_bytes().hex()}")

    # Get the public key
    # public_key =

    # Convert the public key to hex
    #public_key_hex = encode_hex(public_key.to_bytes())




    # Save hash to file
    with open('./testdata/hash_to_sign.bin', 'wb') as binary_file:
        binary_file.write(hash_to_sign)

    # Sign the message
    signed_message_hash = sign_message_hash(account._key_obj,hash_to_sign)
    return signed_message_hash

def binary_to_hex(file_path):
    # Read binary data from the file
    with open(file_path, 'rb') as binary_file:
        binary_data = binary_file.read()

    # Convert binary data to hexadecimal string
    hex_string = binascii.hexlify(binary_data).decode('utf-8')

    return hex_string

def recover_address(message, signature):
    w3 = Web3(Web3.HTTPProvider(""))
    message_encoded = encode_defunct(text=message)
    recovered_address = w3.eth.account.recover_message(message_encoded,signature=eth_signature_bytes)

    return recovered_address

def prepare_and_safe_hash(message):
    print(f"Message: {message}")
    #message_encoded = encode_defunct(text=message)
    message_encoded = encode_defunct(message)
    hash_to_sign = _hash_eip191_message(message_encoded)
    print(f"Hash to sign: {hash_to_sign.hex()}")
    print(f"Hash to sign saved in hash_to_sign.bin")
    with open('./testdata/hash_to_sign.bin', 'wb') as binary_file:
            binary_file.write(hash_to_sign)
    return hash_to_sign

def get_address_from_public_key(public_key_bytes):
    address =  keccak(public_key_bytes)[-20:]
    print(f"Address: {address}")
    return address


# Message to sign
with open("./testdata/msg", 'rb') as binary_file:
        message = binary_file.read()
#pubkey_bytes  = binary_to_hex("1.pub")
#get_address_from_public_key(pubkey_bytes)
prepare_and_safe_hash(message)