<?php

namespace Dgcrypt;

/**
 * Class Dgcrypt
 * Provides methods to securely encrypt and decrypt strings using AES-256-CBC, AES-256-GCM, or ChaCha20-Poly1305.
 */
class Dgcrypt
{
    private $iv;  // Initialization vector for encryption
    private $key; // Secret key for encryption and decryption
    private $cipherMethod; // Cipher method

    /**
     * Dgcrypt constructor.
     * Ensures that the OpenSSL extension is installed and sets the cipher method.
     * 
     * @param string $cipherMethod The cipher method (aes-256-cbc, aes-256-gcm, chacha20-poly1305)
     * @throws \Exception if OpenSSL is not installed or the cipher method is not supported
     */
    public function __construct(string $cipherMethod = 'aes-256-cbc')
    {
        if (!function_exists('openssl_encrypt')) {
            throw new \Exception('OpenSSL Library is not installed');
        }
        $this->setCipherMethod($cipherMethod);
    }

    /**
     * Sets the secret key for encryption and decryption based on sha256 hash.
     * Always 32 characters long.
     * 
     * @param string $key
     * @return $this
     */
    public function setKey(string $key)
    {
        $this->key = substr(hash('sha256', $key),0,32);
        return $this;
    }

    /**
     * Auto-generates a secure random key that is 32 characters long.
     * 
     * @return string The generated key
     */
    public function generateKey()
    {
        $this->setKey(openssl_random_pseudo_bytes(32));
        return $this->key;
    }

    /**
     * Sets the initialization vector (IV) for encryption.
     * If no IV is provided, a secure random IV is generated.
     * 
     * @param string|null $iv The IV (must be 12 bytes for GCM or ChaCha20, 16 bytes for CBC)
     * @return $this
     * @throws \Exception if the IV length is not 12 or 16 bytes
     */
    public function setIV(string $iv = null)
    {
        $ivLength = openssl_cipher_iv_length($this->cipherMethod);
        if (empty($iv)) {
            $this->iv = openssl_random_pseudo_bytes($ivLength);
        } else {
            if (strlen($iv) !== $ivLength) {
                throw new \Exception('IV length should be ' . $ivLength . ' bytes for ' . $this->cipherMethod);
            }
            $this->iv = $iv;
        }
        return $this;
    }

    /**
     * Sets the cipher method.
     * 
     * @param string $method The cipher method (aes-256-cbc, aes-256-gcm, chacha20-poly1305)
     * @return $this
     * @throws \Exception if the method is not supported
     */
    public function setCipherMethod(string $method)
    {
        $supportedMethods = ['aes-256-cbc', 'aes-256-gcm', 'chacha20-poly1305'];
        if (!in_array($method, $supportedMethods)) {
            throw new \Exception('Cipher method not supported');
        }
        $this->cipherMethod = $method;
        return $this;
    }

    /**
     * Encrypts a given string.
     * 
     * @param string $string The input string to encrypt
     * @param string|null $secretKey Optional secret key for encryption
     * @param bool $resetIV Whether to reset the IV after encryption
     * @return string The encrypted string, base64 encoded
     * @throws \Exception if the secret key is not defined or encryption fails
     */
    public function encrypt(string $string, string $secretKey = null, bool $resetIV = true)
    {
        if (!empty($secretKey)) {
            $this->setKey($secretKey);
        } elseif (empty($this->key)) {
            throw new \Exception('Secret key is not defined');
        }

        if (empty($this->iv)) {
            $this->setIV();
        }

        $tag = null;

        switch ($this->cipherMethod) {
            case 'aes-256-cbc':
                $encryptedString = openssl_encrypt(
                    $string,
                    $this->cipherMethod,
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $this->iv
                );
                break;
            case 'aes-256-gcm':
            case 'chacha20-poly1305':
                $encryptedString = openssl_encrypt(
                    $string,
                    $this->cipherMethod,
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $this->iv,
                    $tag
                );
                break;
            default:
                throw new \Exception('Unsupported cipher method');
        }

        if ($encryptedString === false) {
            throw new \Exception('Encryption failed: ' . openssl_error_string());
        }

        // Base 64 encode the encrypted string
        $encryptedString = base64_encode(bin2hex($encryptedString));
        // Convert tag to hex
        if (!empty($tag)) {
            $tag = bin2hex($tag);
        }

        // Add IV and tag to the encrypted string
        $encryptedString = base64_encode(bin2hex($this->iv) . $tag . $encryptedString);

        if ($resetIV) {
            $this->iv = null;
        }

        return $encryptedString;
    }

    /**
     * Decrypts a given string.
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
        // First Base64 decode the encrypted string
        $decodedString = base64_decode($string);
        if ($decodedString === false) {
            throw new \Exception('Encoded string is manipulated or corrupted');
        }

        $ivLength = openssl_cipher_iv_length($this->cipherMethod);
        $tagLength = ($this->cipherMethod === 'aes-256-gcm' || $this->cipherMethod === 'chacha20-poly1305') ? 16 : 0;

        // Extract IV and tag from the decoded string
        $iv = hex2bin(substr($decodedString, 0, $ivLength * 2)); // hex string is twice the length of binary
        $tag = ($tagLength > 0) ? hex2bin(substr($decodedString, $ivLength * 2, $tagLength * 2)) : null;

        $encryptedData = substr($decodedString, ($ivLength + $tagLength) * 2);

        // Second Base64 decode the encrypted data
        $encryptedData = hex2bin(base64_decode($encryptedData));

        switch ($this->cipherMethod) {
            case 'aes-256-cbc':
                $decryptedString = openssl_decrypt(
                    $encryptedData,
                    $this->cipherMethod,
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $iv
                );
                break;
            case 'aes-256-gcm':
            case 'chacha20-poly1305':
                $decryptedString = openssl_decrypt(
                    $encryptedData,
                    $this->cipherMethod,
                    $this->key,
                    OPENSSL_RAW_DATA,
                    $iv,
                    $tag
                );
                break;
            default:
                throw new \Exception('Unsupported cipher method');
        }
        if ($decryptedString === false) {
            throw new \Exception('Decryption failed: ' . openssl_error_string());
        }

        return $decryptedString;
    }
}
