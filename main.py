import pyspx.sha2_128s as sphincsS
import pyspx.sha2_128f as sphincsF
import os, binascii
import time

# Key generation: private + public key
print("Using Slow")
start_time = time.time()
seed = os.urandom(sphincsS.crypto_sign_SEEDBYTES)
public_key, secret_key = sphincsS.generate_keypair(seed)
print("Public key:", binascii.hexlify(public_key), "(32 bytes)")
print("Private key:", binascii.hexlify(secret_key), "(64 bytes)")
print("--- %s seconds ---" % (time.time() - start_time))

# Sign message and verify signature
#inputted = input()
inputted = "This paper is the best!"
start_time = time.time()
message = bytes(inputted, 'utf-8')
signature = sphincsS.sign(message, secret_key)
valid = sphincsS.verify(message, signature, public_key)
print("Sign the message and the signature:")
print("Message:", message)
print("Signature:", binascii.hexlify(signature), "(7856)")
print("Is the signature valid", valid)
print("--- %s seconds ---" % (time.time() - start_time))

print("Using Fast")
# Key generation: private + public key
start_time = time.time()
seed = os.urandom(sphincsF.crypto_sign_SEEDBYTES)
public_key, secret_key = sphincsF.generate_keypair(seed)
print("Public key:", binascii.hexlify(public_key), "(32 bytes)")
print("Private key:", binascii.hexlify(secret_key), "(64 bytes)")
print("--- %s seconds ---" % (time.time() - start_time))

# Sign message and verify signature
#inputted = input()
inputted = "This paper is so good!"
start_time = time.time()
message = bytes(inputted, 'utf-8')
signature = sphincsF.sign(message, secret_key)
valid = sphincsF.verify(message, signature, public_key)
print("Sign the message and the signature:")
print("Message:", message)
print("Signature:", binascii.hexlify(signature), "(17088)")
print("Is the signature valid", valid)
print("--- %s seconds ---" % (time.time() - start_time))

