from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

#generate 1024 bit RSA key
keyPair = RSA.generate(bits=1024)
pubKey = keyPair.publickey()

msg =b'Messgaes to be signed'
hash = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hash)
print("Signature:", binascii.hexlify(signature))

#verify signature PKcS1_15 v1.5 signature (RSAVP1)
msg =b'Messgaes to be signed'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash,signature)
    print("Signature is valid")
except:
    print("Signature is invalid")


# Verify invalid PKCS#1 v1.5 signature (RSAVP1)
msg = b'A tampered message'
hash = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")