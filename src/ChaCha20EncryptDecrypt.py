import base64
import hashlib
import pysodium

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