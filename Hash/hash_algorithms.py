import hashlib
import sha3  # pysha3 library is required

def hash_message(message):
    """
    Calculates the hash of a message using various algorithms.

    Args:
        message: The text message to hash (bytes).

    Returns:
        A dictionary containing the calculated hashes for each algorithm.
    """
    hashes = {}
    hashes["SHA-224"] = hashlib.sha224(message).hexdigest()
    hashes["SHA-256"] = hashlib.sha256(message).hexdigest()
    hashes["SHA3-224"] = hashlib.sha3_224(message).hexdigest()
    hashes["SHA3-384"] = hashlib.sha3_384(message).hexdigest()
    hashes["Keccak-384"] = sha3.keccak_384(message).hexdigest()
    return hashes

# Example usage
text_message = b"This is a secret message!"
hash_results = hash_message(text_message)

print("Hash Results:")
for algorithm, hash_value in hash_results.items():
    print(f"{algorithm}: {hash_value}")
