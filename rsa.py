# importáljuk a szükséges csomagokat
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# generáljuk a kulcsokat
key = RSA.generate(2048)

# konvertáljuk a publikus kulcsot string formátumba
pub_key_str = key.publickey().export_key('PEM').decode()

# konvertáljuk a privát kulcsot string formátumba
priv_key_str = key.export_key('PEM').decode()

# a szöveg, amit titkosítunk
plaintext = "Ez egy szöveg, amit szeretnék titkosítani"

# inicializáljuk a titkosító objektumot a publikus kulccsal
cipher = PKCS1_OAEP.new(RSA.import_key(pub_key_str))

# titkosítjuk a szöveget és base64 kódoljuk az eredményt
ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

print("Titkosított üzenet:", ciphertext)

# inicializáljuk a visszafejtő objektumot a privát kulccsal
cipher = PKCS1_OAEP.new(RSA.import_key(priv_key_str))

# visszafejtjük a titkosított üzenetet és dekódoljuk a base64 formátumot
decrypted = cipher.decrypt(base64.b64decode(ciphertext)).decode()

print("Visszafejtett üzenet:", decrypted)
