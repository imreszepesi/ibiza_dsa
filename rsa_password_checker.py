from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair
key = RSA.generate(2048)

# Get public and private keys
private_key = key.export_key()
public_key = key.publickey().export_key()

# Encrypt password using public key
password = b"kukasauto"
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_password = cipher_rsa.encrypt(password)

# Decrypt password using private key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_password = cipher_rsa.decrypt(encrypted_password)

# Ask for password until correct one is given
while True:
    user_input = input("Enter password: ").encode()
    if user_input == decrypted_password:
        print("Password is correct!")
        break
    else:
        print("Password is incorrect. Please try again.")
