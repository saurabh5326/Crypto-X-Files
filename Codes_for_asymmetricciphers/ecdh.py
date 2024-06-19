import secrets

from tinyec import registry

def compress(pubKey):
  return hex(pubKey.x) + hex(pubKey.y % 2)[2:]
  
curve = registry.get_curve('brainpoolP256r1')

alicePrivKey = secrets.randbelow(curve.field.n)
alicePubKey = alicePrivKey * curve.g
print("Alice public key:", alicePubKey)
print("Compress Alice Public key:", compress(alicePubKey))

bobPrivKey = secrets.randbelow(curve.field.n)
bobPubKey = bobPrivKey * curve.g
print("Bob public key:", bobPubKey)

print("Now exchange the public keys securely (e.g. through TLS)")

aliceSharedKey = alicePrivKey * bobPubKey
print("Alice shared key:", aliceSharedKey)

bobSharedKey = bobPrivKey * alicePubKey
print("Bob shared key:", bobSharedKey)

print("Equal shared keys:", aliceSharedKey == bobSharedKey)
