<?php

namespace Dgcrypt;

/**
 * Class Dgcrypt
 * Provides methods to securely encrypt and decrypt strings using AES-256-CBC.
 */
class Dgcrypt
{
    private $iv;  // Initialization vector for encryption
    private $key; // Secret key for encryption

    /**
     * Dgcrypt constructor.
     * Ensures that the OpenSSL extension is installed.
     * 
     * @throws \Exception if OpenSSL is not installed
     */
    public function __construct()
    {
        if (!function_exists('openssl_encrypt')) {
            throw new \Exception('OpenSSL Library is not installed');
        }
    }

    /**
     * Sets the secret key for encryption and decryption.
     * 
     * @param string $key The secret key (must be 32 characters)
     * @return $this
     * @throws \Exception if the key length is not 32 characters
     */
    public function setKey(string $key)
    {
        if (strlen($key) !== 32) {
            throw new \Exception('Secret key should be 32 characters');
        }
        $this->key = $key;
        return $this;
    }

    /**
     * Sets the initialization vector (IV) for encryption.
     * If no IV is provided, a secure random IV is generated.
     * 
     * @param string|null $iv The IV (must be 16 bytes)
     * @return $this
     * @throws \Exception if the IV length is not 16 bytes
     */
    public function setIV(string $iv = null)
    {
        if (empty($iv)) {
            $iv = openssl_random_pseudo_bytes(16);
        } else {
            if (strlen($iv) !== 16) {
                throw new \Exception('IV should be 16 bytes');
            }
        }
        $this->iv = $iv;
        return $this;
    }

    /**
     * Encrypts a given string using AES-256-CBC.
     * 
     * @param string $string The input string to encrypt
     * @param string|null $secretKey Optional secret key for encryption
     * @param bool $resetIV Whether to reset the IV after encryption
     * @return string The encrypted string, base64 encoded
     * @throws \Exception if the secret key is not defined or encryption fails
     */
    public function encrypt(string $string, string $secretKey = null, bool $resetIV = false)
    {
        if (!empty($secretKey)) {
            $this->setKey($secretKey);
        } elseif (empty($this->key)) {
            throw new \Exception('Secret key is not defined');
        }

        if (empty($this->iv)) {
            $this->setIV();
        }

        $encryptedString = openssl_encrypt($string, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $this->iv);
        if ($encryptedString === false) {
            throw new \Exception('Encryption failed');
        }

        if ($resetIV) {
            $this->iv = null;
        }

        $encryptedString = base64_encode($this->iv . $encryptedString);
        return $encryptedString;
    }

    /**
     * Decrypts a given string using AES-256-CBC.
     * 
     * @param string $string The encrypted string to decrypt (base64 encoded)
     * @param string|null $secretKey Optional secret key for decryption
     * @return string The decrypted string
     * @throws \Exception if the secret key is not defined, the encoded string is corrupted, or decryption fails
     */
    public function decrypt(string $string, string $secretKey = null)
    {
        if (!empty($secretKey)) {
            $this->setKey($secretKey);
        } elseif (empty($this->key)) {
            throw new \Exception('Key for decrypting is not defined');
        }

        $decodedString = base64_decode($string);
        if ($decodedString === false || strlen($decodedString) <= 16) {
            throw new \Exception('Encoded string is manipulated or corrupted');
        }

        $iv = substr($decodedString, 0, 16);
        $encryptedString = substr($decodedString, 16);

        $decryptedString = openssl_decrypt($encryptedString, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $iv);
        if ($decryptedString === false) {
            throw new \Exception('Decryption failed');
        }

        return $decryptedString;
    }
}
