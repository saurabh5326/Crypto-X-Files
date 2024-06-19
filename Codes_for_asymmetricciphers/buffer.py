from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg: bytes, secret_key: bytes) -> tuple[bytes, bytes, bytes]:
  """
  Encrypts a message using AES-GCM with a provided secret key.

  Args:
      msg: The message to encrypt (bytes).
      secret_key: The secret key for encryption (bytes).

  Returns:
      A tuple containing the ciphertext, nonce, and authentication tag.
  """
  aes_cipher = AES.new(secret_key, AES.MODE_GCM)
  ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
  return ciphertext, aes_cipher.nonce, auth_tag

def decrypt_AES_GCM(ciphertext: bytes, nonce: bytes, auth_tag: bytes, secret_key: bytes) -> bytes:
  """
  Decrypts a message encrypted with AES-GCM using the provided secret key, nonce, and authentication tag.

  Args:
      ciphertext: The encrypted message (bytes).
      nonce: The random nonce used for encryption (bytes).
      auth_tag: The authentication tag for data integrity verification (bytes).
      secret_key: The secret key used for encryption (bytes).

  Returns:
      The decrypted message (bytes).
  """
  aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
  plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
  return plaintext

def ecc_point_to_256_bit_key(point) -> bytes:
  """
  Converts an ECC point (shared secret) into a 256-bit key suitable for AES by hashing its x and y coordinates.

  Args:
      point: The ECC point representing the shared secret.

  Returns:
      The derived 256-bit key (bytes).
  """
  sha = hashlib.sha256()
  sha.update(int.to_bytes(point.x, 32, 'big'))
  sha.update(int.to_bytes(point.y, 32, 'big'))
  return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg: bytes, pub_key) -> dict:
  """
  Encrypts a message using a hybrid approach combining ECC and AES-GCM.

  Args:
      msg: The message to encrypt (bytes).
      pub_key: The recipient's public key (ECC point).

  Returns:
      A dictionary containing the encrypted message components.
  """
  # Generate a random private key for this session (ephemeral)
  session_priv_key = secrets.randbelow(curve.field.n)

  # Calculate the shared secret key using ECC
  shared_ecc_key = session_priv_key * pub_key

  # Derive a 256-bit secret key from the shared secret point
  secret_key = ecc_point_to_256_bit_key(shared_ecc_key)

  # Encrypt the message with AES-GCM using the derived key
  ciphertext, nonce, auth_tag = encrypt_AES_GCM(msg, secret_key)

  # Generate a new ephemeral public key from the session private key
  ephemeral_pub_key = session_priv_key * curve.g

  # Return the encrypted message components in a dictionary
  return {
      'ciphertext': binascii.hexlify(ciphertext),
      'nonce': binascii.hexlify(nonce),
      'authTag': binascii.hexlify(auth_tag),
      'ciphertextPubKey': (hex(ephemeral_pub_key.x), hex(ephemeral_pub_key.y % 2)[2:])
  }

def decrypt_ECC(encrypted_msg: dict, priv_key) -> bytes:
  """
  Decrypts a message encrypted using a hybrid approach combining ECC and AES-GCM.

  Args:
      encrypted_msg: A dictionary containing the encrypted message components.
      priv_key: The recipient's private key (ECC point).

  Returns:
      The decrypted message (bytes).
  """
  # Extract components from the encrypted message dictionary
  ciphertext, nonce, auth_tag, (ephemeral_pub_key_x, ephemeral_pub_key_
