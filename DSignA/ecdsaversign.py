from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import hashlib
import secrets

# Define the hash function
def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

# Define the ECDSA signing function
def signECDSAsecp256k1(msg, privKey):
    msgHash = sha3_256Hash(msg)
    signature = privKey.sign_deterministic(msgHash.to_bytes(32, byteorder="big"), hashfunc=hashlib.sha3_256)
    return signature

# Define the ECDSA signature verification function
def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    try:
        valid = pubKey.verify(signature, msgHash.to_bytes(32, byteorder="big"), hashfunc=hashlib.sha3_256)
    except BadSignatureError:
        valid = False
    return valid

# Main function to sign a message and verify its signature
msg = "A message for ECDSA signing"
privKey = SigningKey.generate(curve=SECP256k1)
pubKey = privKey.get_verifying_key()

signature = signECDSAsecp256k1(msg, privKey)
print("Message:", msg)
print("Private key:", privKey.to_string().hex())
print("Signature:", signature.hex())

# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Public key:", pubKey.to_string().hex())
print("Signature valid:", valid)

# ECDSA verify signature (tampered msg)
msg = "A tampered message"
valid = verifyECDSAsecp256k1(msg, signature, pubKey)
print("\nMessage:", msg)
print("Signature valid:", valid)
