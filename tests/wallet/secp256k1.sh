#!/bin/bash
#-eu

#GITROOT=$(git rev-parse --show-toplevel)
cd /pico-hsm/tests/wallet
############
#cleaning up and setting message
rm  testdata/*
echo "AAAAAA" > testdata/msg
#restarting pcscd because it's crap
service pcscd restart

# generating pair and extracting public key in eth-compatable format
pkcs11-tool -l --pin 648219 --delete-object --type privkey --id 1
pkcs11-tool -l --pin 648219 --keypairgen --key-type "ec:secp256k1" --id 1 --label "ETH"
pkcs11-tool --read-object --pin 648219 --id 1 --type pubkey > testdata/1pub.der
openssl ec -inform DER -outform PEM -in testdata/1pub.der -pubin -text > testdata/1pub.pem
openssl ec -inform DER -outform PEM -in testdata/1pub.der -pubin -text | grep "    " | tr -d ' :\n' | cut -c 3- > testdata/1pub.eth


#generating address
python3 ./convert.sh

#preparing message
python3 ./eth_prepare_message.py


#signin the data
pkcs11-tool --id 1 --sign --pin 648219 --mechanism ECDSA -i testdata/hash_to_sign.bin -o testdata/signature_openssl.der --signature-format openssl
pkcs11-tool --id 1 --sign --pin 648219 --mechanism ECDSA -i testdata/hash_to_sign.bin -o testdata/signature.der
#cheking signature with openssl
openssl pkeyutl -verify -pubin -inkey testdata/1pub.pem -in testdata/hash_to_sign.bin -sigfile testdata/signature_openssl.der


#recovering address from signature
python3 ./ethvalid.py
date