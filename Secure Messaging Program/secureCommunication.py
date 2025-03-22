# Applied Cryptography Final Project Fall 2023
# Authors: Derek Hopkins, Jacob Nevin, Ethan Conner
# This program uses Elliptic Curve Diffie-Hellman for session key distribution (authorization)
# AES-256 in CBC Mode is used for confidentiality
# SHA-256 is used for authentication

# Required Packages:
# tinyec
# pycryptodome

import binascii
from tinyec import registry
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Padding
import base64

def compress(pubKey):
    compressedKey = hex(pubKey.x) + hex(pubKey.y % 2)[2:]
    return compressedKey

def ecdhKeyExchange():

    curve = registry.get_curve('secp256r1')
    alicePrivKey = secrets.randbelow(curve.field.n)
    alicePubKey = alicePrivKey * curve.g
    print("Alice public key:", compress(alicePubKey))

    bobPrivKey = secrets.randbelow(curve.field.n)
    bobPubKey = bobPrivKey * curve.g
    print("Bob public key:", compress(bobPubKey))

    print("\nPublic keys can now be exchanged insecurely :)\n")

    aliceSharedKey = alicePrivKey * bobPubKey
    print("Alice shared key:", compress(aliceSharedKey))

    bobSharedKey = bobPrivKey * alicePubKey
    print("Bob shared key:", compress(bobSharedKey))

    print("Equal shared keys:", aliceSharedKey == bobSharedKey)
    
    sesKeyTransform = compress(aliceSharedKey)
   
    sesKeyTransform = sesKeyTransform[2:]
    if(len(sesKeyTransform) % 2 == 1):
        sesKeyTransform = sesKeyTransform[:-1]
    
    print("\nTransformed Key: ", sesKeyTransform, "\n")
    
    return binascii.unhexlify(sesKeyTransform)

def initialVectorExchange():
    
    curve = registry.get_curve('secp256r1')
    alicePrivIV = secrets.randbelow(curve.field.n)
    alicePubIV = alicePrivIV * curve.g
    print("Alice public IV:", compress(alicePubIV))

    bobPrivIV = secrets.randbelow(curve.field.n)
    bobPubIV = bobPrivIV * curve.g
    print("Bob public IV:", compress(bobPubIV))

    print("\nPublic IVs can now be exchanged insecurely :)\n")

    aliceSharedIV = alicePrivIV * bobPubIV
    print("Alice shared IV:", compress(aliceSharedIV))

    bobSharedIV = bobPrivIV * alicePubIV
    print("Bob shared IV:", compress(bobSharedIV))

    print("Equal shared IVs:", aliceSharedIV == bobSharedIV)
    
    sesIVTransform = compress(aliceSharedIV)
   
    sesIVTransform = sesIVTransform[2:]
    if(len(sesIVTransform) % 2 == 1):
        sesIVTransform = sesIVTransform[:-1]
    # makes it a 16 byte IV
    sesIVTransform = sesIVTransform[:len(sesIVTransform)//2]
    print("\nTransformed IV: ", sesIVTransform, "\n")
    
    return binascii.unhexlify(sesIVTransform)


def encrypt(pTextMsg, sesKey):

    # AES-256 in CBC Mode using session-key as encryption key
    
    iv = sharedIV

    byteString = pTextMsg.encode('utf-8')

    paddedBString = Padding.pad(byteString, 16, 'pkcs7')

    print("Raw Text: ", pTextMsg, "\n")
    print("Padded Text: ", paddedBString, "\n")

    cipher = AES.new(sesKey, AES.MODE_CBC, iv)

    cText = cipher.encrypt(paddedBString)

    return {
       'cipher_text': base64.b64encode(cText),
       'iv': base64.b64encode(iv)
    }

def decrypt(encryption_dict, sesKey):

    cText = base64.b64decode(encryption_dict['cipher_text'])

    iv = sharedIV

    cipher = AES.new(sesKey, AES.MODE_CBC, iv)

    decryption = cipher.decrypt(cText)

    pTextMsg = Padding.unpad(decryption, 16, 'pkcs7')

    pTextMsg = pTextMsg.decode('utf-8')

    return pTextMsg
   

def hashMsg(string):
    h = hashlib.sha256()
    b = string.encode('utf-8')
    h.update(b)
    hashedMsg = h.digest()
    return hashedMsg


pTextMsg = input("Enter a message: ")

sessionKey = ecdhKeyExchange()

sharedIV = initialVectorExchange()

hashedPlaintext = hashMsg(pTextMsg)

print("Hashed Plaintext: ", hashedPlaintext,"\n")

enc_dict = encrypt(pTextMsg, sessionKey)

cipherText = base64.b64decode(enc_dict['cipher_text'])

print("Cipher Text ==> ", cipherText, "\n")

decryptedCipherText = decrypt(enc_dict, sessionKey)

print("Decrypted Cipher Text ==> ", decryptedCipherText, "\n")

hashedDecryption = hashMsg(decryptedCipherText)

print("Hashed decryption: ", hashedDecryption, "\n")

print("Data Intact: ", hashedDecryption == hashedPlaintext)
