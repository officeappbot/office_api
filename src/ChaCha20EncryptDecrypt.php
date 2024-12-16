<?php

class ChaCha20EncryptDecrypt
{
    private string $key;
    private string $nonce;

    public function __construct(string $key)
    {
        $this->key = sodium_crypto_generichash($key, '', 32);
        $this->nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
    }

    public function encrypt(string $data): string
    {
        $ciphertext = sodium_crypto_stream_xor($data, $this->nonce, $this->key);
        return base64_encode($this->nonce . $ciphertext);
    }

    public function decrypt(string $data): string
    {
        $decoded = base64_decode($data);
        $nonce = substr($decoded, 0, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $ciphertext = substr($decoded, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        return sodium_crypto_stream_xor($ciphertext, $nonce, $this->key);
    }
}