from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Kulcs generálása
key = DSA.generate(2048)

# Az üzenet bekérése a felhasználótól
message = input("Írja be az üzenetet: ").encode()

# Az aláírás generálása
hash_object = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(hash_object)

# Az aláírás ellenőrzése
hash_object = SHA256.new(message)
verifier = DSS.new(key.publickey(), 'fips-186-3')
try:
    verifier.verify(hash_object, signature)
    print("Az aláírás érvényes.")
except ValueError:
    print("Az aláírás érvénytelen.")
