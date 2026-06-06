<?php

namespace JarirAhmed\Encryptor;

/**
 * Authenticated symmetric encryption.
 *
 * Default cipher is AES-256-GCM (AEAD: confidentiality + integrity). For non-AEAD ciphers
 * (e.g. AES-256-CBC, AES-256-CTR) an encrypt-then-HMAC scheme is applied so ciphertexts
 * are always tamper-evident. Output format: base64( iv | tag-or-hmac | ciphertext ).
 */
class Encryptor
{
    /** @var string */
    private $cipher;
    /** @var string 32-byte encryption key */
    private $encKey;
    /** @var string 32-byte MAC key (non-AEAD ciphers only) */
    private $macKey;
    /** @var int */
    private $ivLength;
    /** @var bool */
    private $isAead;

    const HMAC_ALGO = 'sha256';
    const HMAC_LEN = 32;
    const GCM_TAG_LEN = 16;

    /**
     * @param string $key    Secret key. Stretched to 32 bytes via SHA-256.
     * @param string $cipher OpenSSL cipher name. Default AES-256-GCM.
     */
    public function __construct($key, $cipher = 'aes-256-gcm')
    {
        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('Encryption key must be a non-empty string.');
        }
        $cipher = strtolower($cipher);
        if (!in_array($cipher, array_map('strtolower', openssl_get_cipher_methods()), true)) {
            throw new \InvalidArgumentException("Cipher method {$cipher} is not supported.");
        }

        $this->cipher = $cipher;
        // Domain-separated keys so the MAC key never equals the encryption key.
        $this->encKey = hash('sha256', 'enc|' . $key, true);
        $this->macKey = hash('sha256', 'mac|' . $key, true);
        $this->ivLength = (int) openssl_cipher_iv_length($cipher);
        $this->isAead = (strpos($cipher, 'gcm') !== false || strpos($cipher, 'ccm') !== false);
    }

    /**
     * @param string $data Plaintext.
     * @return string Base64-encoded, authenticated ciphertext.
     */
    public function encrypt($data)
    {
        $iv = $this->ivLength > 0 ? random_bytes($this->ivLength) : '';

        if ($this->isAead) {
            $tag = '';
            $ct = openssl_encrypt(
                $data, $this->cipher, $this->encKey, OPENSSL_RAW_DATA, $iv, $tag, '', self::GCM_TAG_LEN
            );
            if ($ct === false) {
                throw new \RuntimeException('Encryption failed.');
            }
            return base64_encode($iv . $tag . $ct);
        }

        $ct = openssl_encrypt($data, $this->cipher, $this->encKey, OPENSSL_RAW_DATA, $iv);
        if ($ct === false) {
            throw new \RuntimeException('Encryption failed.');
        }
        $mac = hash_hmac(self::HMAC_ALGO, $iv . $ct, $this->macKey, true);
        return base64_encode($iv . $mac . $ct);
    }

    /**
     * @param string $data Base64-encoded ciphertext produced by encrypt().
     * @return string Plaintext.
     */
    public function decrypt($data)
    {
        $decoded = base64_decode((string) $data, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64 encoded data.');
        }

        if ($this->isAead) {
            $min = $this->ivLength + self::GCM_TAG_LEN;
            if (strlen($decoded) < $min) {
                throw new \InvalidArgumentException('Ciphertext too short.');
            }
            $iv = substr($decoded, 0, $this->ivLength);
            $tag = substr($decoded, $this->ivLength, self::GCM_TAG_LEN);
            $ct = substr($decoded, $min);
            $pt = openssl_decrypt($ct, $this->cipher, $this->encKey, OPENSSL_RAW_DATA, $iv, $tag);
            if ($pt === false) {
                throw new \RuntimeException('Decryption failed (data tampered or wrong key).');
            }
            return $pt;
        }

        $min = $this->ivLength + self::HMAC_LEN;
        if (strlen($decoded) < $min) {
            throw new \InvalidArgumentException('Ciphertext too short.');
        }
        $iv = substr($decoded, 0, $this->ivLength);
        $mac = substr($decoded, $this->ivLength, self::HMAC_LEN);
        $ct = substr($decoded, $min);

        $expected = hash_hmac(self::HMAC_ALGO, $iv . $ct, $this->macKey, true);
        if (!hash_equals($expected, $mac)) {
            throw new \RuntimeException('Decryption failed (data tampered or wrong key).');
        }

        $pt = openssl_decrypt($ct, $this->cipher, $this->encKey, OPENSSL_RAW_DATA, $iv);
        if ($pt === false) {
            throw new \RuntimeException('Decryption failed.');
        }
        return $pt;
    }
}
