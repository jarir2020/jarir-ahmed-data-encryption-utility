<?php
// src/Encryptor.php

namespace JarirAhmed\Encryptor;

class Encryptor
{
    private $cipher;
    private $key;
    private $ivLength;

    public function __construct(string $key, string $cipher = 'AES-256-CBC')
    {
        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            throw new \InvalidArgumentException("Cipher method {$cipher} is not supported.");
        }

        $this->cipher = $cipher;
        $this->key = hash('sha256', $key, true); // Ensure the key is 32 bytes for AES-256
        $this->ivLength = openssl_cipher_iv_length($this->cipher);
    }

    /**
     * Encrypts the given data.
     *
     * @param string $data Plain text data to encrypt.
     * @return string Base64 encoded encrypted data with IV.
     */
    public function encrypt(string $data): string
    {
        $iv = random_bytes($this->ivLength);
        $encrypted = openssl_encrypt($data, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            throw new \RuntimeException('Encryption failed.');
        }

        // Combine IV and encrypted data for storage/transmission
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypts the given data.
     *
     * @param string $data Base64 encoded encrypted data with IV.
     * @return string Decrypted plain text data.
     */
    public function decrypt(string $data): string
    {
        $decoded = base64_decode($data, true);

        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64 encoded data.');
        }

        $iv = substr($decoded, 0, $this->ivLength);
        $encryptedData = substr($decoded, $this->ivLength);

        if ($iv === false || $encryptedData === false) {
            throw new \InvalidArgumentException('Invalid data format.');
        }

        $decrypted = openssl_decrypt($encryptedData, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            throw new \RuntimeException('Decryption failed.');
        }

        return $decrypted;
    }
}
