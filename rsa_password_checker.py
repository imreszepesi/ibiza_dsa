from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair
key = RSA.generate(2048)

# Get public and private keys
private_key = key.export_key()
public_key = key.publickey().export_key()

# Write private key to file
with open("private_key.pem", "wb") as f:
    f.write(private_key)

# Encrypt password using public key
password = b"mysecretpassword"
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_password = cipher_rsa.encrypt(password)

# Write encrypted password to file
with open("encrypted_password.bin", "wb") as f:
    f.write(encrypted_password)

# Read encrypted password from file
with open("encrypted_password.bin", "rb") as f:
    encrypted_password = f.read()

# Decrypt password using private key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_password = cipher_rsa.decrypt(encrypted_password)

# Read user input and compare with decrypted password
user_input = input("Enter password: ").encode()
if user_input == decrypted_password:
    print("Password is correct!")
else:
    print("Password is incorrect!")
