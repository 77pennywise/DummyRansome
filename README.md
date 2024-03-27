# DummyRansome
Ransomeware Encrypts file data using two encryption tools (AES and RSA) in Python:

AES Encryption: 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
This line imports necessary libraries for encryption and decryption, including AES and RSA encryption algorithms, along with functions for generating random bytes.


Function Definitions - AES Encryption:
 
def encrypt_aes(data, key):
Defines a function encrypt_aes that takes data and an AES key as input for encryption.
 
cipher = AES.new(key, AES.MODE_EAX)
Initializes an AES cipher with the provided key using Electronic Codebook (ECB) mode.
 
ciphertext, tag = cipher.encrypt_and_digest(data.encode())
Encrypts the data using AES encryption and generates a ciphertext along with an authentication tag.
 
return cipher.nonce, tag, ciphertext
Returns the nonce (a unique value used only once), the authentication tag, and the ciphertext.
 
def decrypt_aes(nonce, tag, ciphertext, key):
Defines a function decrypt_aes that takes the nonce, tag, ciphertext, and AES key for decryption.
 
cipher = AES.new(key, AES.MODE_EAX, nonce)
Initializes an AES cipher with the provided key and nonce.
 
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
Decrypts the ciphertext using AES decryption and verifies its authenticity using the tag.
 
return plaintext.decode()
Returns the decrypted plaintext data in a readable format.


Function Definitions - RSA Encryption:
 
def encrypt_rsa(data, public_key_file):
Defines a function encrypt_rsa that takes data and the path to a public key file for RSA encryption.
 
def decrypt_rsa(ciphertext, private_key_file):
Defines a function decrypt_rsa that takes ciphertext and the path to a private key file for RSA decryption.
 
if __name__ == "__main__":
Executes the following code block only if the script is executed directly.
 
aes_key = get_random_bytes(16)
Generates a random 16-byte (128-bit) AES key for encryption.
 
data = "This is a secret message."
Defines a sample message to be encrypted.
 
aes_nonce, aes_tag, aes_ciphertext = encrypt_aes(data, aes_key)
Encrypts the sample message using AES encryption and retrieves the nonce, tag, and ciphertext.
 
decrypted_data_aes = decrypt_aes(aes_nonce, aes_tag, aes_ciphertext, aes_key)
Decrypts the AES ciphertext using the nonce, tag, ciphertext, and AES key, resulting in the original plaintext data.
 
rsa_ciphertext = encrypt_rsa(data, rsa_public_key_file)
Encrypts the sample message using RSA encryption and the specified public key file.
 
decrypted_data_rsa = decrypt_rsa(rsa_ciphertext, rsa_private_key_file)
Decrypts the RSA ciphertext using the specified private key file, resulting in the original plaintext data.
Printing Decrypted Data:
 
print("Decrypted AES Data:", decrypted_data_aes)
Prints the decrypted data obtained from AES decryption.
 
print("Decrypted RSA Data:", decrypted_data_rsa)
Prints the decrypted data obtained from RSA decryption.
This breakdown explains how each line of the code contributes to the process of encrypting and decrypting data using AES and RSA encryption algorithms.
