# package pycoin implements the ECDSA signature scheme
# First, define the functions for hashing, ECDSA signing and ECDSA signature verification
from pycoin.ecdsa import generator_secp256k1, sign, verify
from hashlib, secrets

# Define the hash function
def sha3_256Hash(msg):
    hashBytes = hash