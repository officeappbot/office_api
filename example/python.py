import requests
import time
import base64
import hashlib
import pysodium

# Secret and public keys
secret_key = 'SECRET-KEY'
public_key = 'PUBLIC-KEY'

# Step 1: Get the phrase
url = 'https://rest-api.officebot.app/api/get-phrase'
headers = {'Accept': 'application/json'}
response = requests.get(url, headers=headers)

if response.status_code == 200:
    result = response.json()
    if 'data' in result and 'phrase' in result['data']:
        # Step 2: Add current time to the phrase
        phrase = result['data']['phrase'] + '|' + str(int(time.time()))

        # Step 3: Encrypt the phrase with the secret key
        encryptor = XSalsa20EncryptDecrypt(secret_key)
        enc = encryptor.encrypt(phrase)

        # Step 4: Create the final token
        final_token = public_key + '|' + enc
        print(final_token)
    else:
        print('no phrase')
else:
    print('Failed to get phrase')

class XSalsa20EncryptDecrypt:
    def __init__(self, key: str):        
        self.key = hashlib.blake2b(key.encode('utf-8'), digest_size=32).digest()

    def encrypt(self, data: str) -> str:        
        nonce = pysodium.randombytes(pysodium.crypto_stream_NONCEBYTES)        
        ciphertext = pysodium.crypto_stream_xor(data.encode('utf-8'), len(data), nonce, self.key)        
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, data: str) -> str:        
        decoded = base64.b64decode(data)        
        nonce = decoded[:pysodium.crypto_stream_NONCEBYTES]
        ciphertext = decoded[pysodium.crypto_stream_NONCEBYTES:]        
        decrypted = pysodium.crypto_stream_xor(ciphertext, len(ciphertext), nonce, self.key)
        return decrypted.decode('utf-8')

