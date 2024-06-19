from tinyec import registry
import secrets

curve = registry.get_curve('brainpoolP256r1')

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def ecc_calc_encryption_keys(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def ecc_calc_decryption_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey
#Sender side key generation
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
print("private key:", hex(privKey))
print("public key:", compress_point(pubKey))
#Receiver side key generation
(encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)
print("ciphertext pubKey:", compress_point(ciphertextPubKey))
print("encryption key:", compress_point(encryptKey))

decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)
print("decryption key:", compress_point(decryptKey))

#It is clear from the above output that the encryption key (derived from the public key) and the decryption key (derived from the #corresponding private key) are the same.
#The code is pretty simple and demonstrates that we can generate a pair { secret key + ciphertext public key } from given EC public key #and later we can recover the same secret key from the pair { ciphertext public key + private key }. 
#The above output will be different if you run the code (due to the randomness used to generate ciphertextPrivKey, but the encryption #and decryption keys will always be the same (the ECDH shared secret).
#This is due to the above discussed property of the ECC: pubKey * ciphertextPrivKey = ciphertextPubKey * privKey. These keys will be #used for data encryption and decryption in an integrated encryption scheme.
