from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Function to encrypt data using AES encryption
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce, tag, ciphertext

# Function to decrypt data using AES encryption
def decrypt_aes(nonce, tag, ciphertext, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Function to encrypt data using RSA encryption
def encrypt_rsa(data, public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(data.encode())
    return ciphertext

# Function to decrypt data using RSA encryption
def decrypt_rsa(ciphertext, private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext.decode()

# Example usage
if __name__ == "__main__":
    # AES encryption
    aes_key = get_random_bytes(16)  # Generate a random AES key
    data = "This is a secret message."
    aes_nonce, aes_tag, aes_ciphertext = encrypt_aes(data, aes_key)
    decrypted_data_aes = decrypt_aes(aes_nonce, aes_tag, aes_ciphertext, aes_key)
    print("Decrypted AES Data:", decrypted_data_aes)

    # RSA encryption
    rsa_public_key_file = "public_key.pem"  # Path to the RSA public key file
    rsa_private_key_file = "private_key.pem"  # Path to the RSA private key file
    data = "This is another secret message."
    rsa_ciphertext = encrypt_rsa(data, rsa_public_key_file)
    decrypted_data_rsa = decrypt_rsa(rsa_ciphertext, rsa_private_key_file)
    print("Decrypted RSA Data:", decrypted_data_rsa)
