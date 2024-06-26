# rough skelton for building Sicomac cipher

from speck import SPECK

block_size = 64
key_size = 128
master_key = 0x1b1a1918131211100b0a090803020100

# Create an instance of the SPECK cipher
speck = SPECK(block_size, key_size, master_key)

# Define plaintext
plaintext = 0x3b7265747475432d

# Encrypt the plaintext
ciphertext = speck.encrypt(plaintext)
print(f"Ciphertext: {ciphertext:x}")

# Decrypt the ciphertext
decrypted_text = speck.decrypt(ciphertext)
print(f"Decrypted text: {decrypted_text:x}")

# Verify that the decrypted text matches the original plaintext
assert decrypted_text == plaintext
print("Encryption and decryption are successful and match the original plaintext.")
