# Dgcrypt

Dgcrypt is a simple PHP library for encryption and decryption using multiple encryption methods including **AES-256-CBC**, **AES-256-GCM**, and **ChaCha20-Poly1305**. It is designed to securely encrypt data on the backend, which can then be easily decrypted on the client side, such as on Android and iOS devices. This ensures that the data remains secure during transmission and cannot be easily cracked in between.

## Platform Compatibility
The Dgcrypt library is designed to work seamlessly across multiple platforms. You can find corresponding libraries for the following platforms:

- **Android**: [Dgcrypt-Android](https://github.com/davodm/dgcrypt-android)
- **Node.js**: [Dgcrypt-Node](https://github.com/davodm/dgcrypt-node)

These libraries allow you to easily decrypt data that was encrypted on the backend using this PHP library, ensuring secure communication between your backend and client applications.

## Supported Encryption Methods
Dgcrypt supports the following encryption methods:
- **AES-256-CBC**: Standard encryption method providing confidentiality.
- **AES-256-GCM**: Provides both encryption and authentication.
- **ChaCha20-Poly1305**: Modern encryption method known for its performance and security.

## Installation

You can install the package via Composer:

```bash
composer require davodm/dgcrypt-php
```

## Usage

### Setting Up
```php
use Dgcrypt\Dgcrypt;

// Initialize the Dgcrypt class with the desired encryption method
$dgcrypt = new Dgcrypt('aes-256-gcm'); // Can be 'aes-256-cbc', 'aes-256-gcm', or 'chacha20-poly1305'

// Set a secret key
$dgcrypt->setKey('your-secret key');
```

### Encrypting Data on the Backend:
```php
// Encrypt a string
$plainText = 'Hello, World!';
$encrypted = $dgcrypt->encrypt($plainText);

// Output the encrypted string
echo $encrypted;
```

### Decrypting Data on the Backend:
```php
// Decrypt the previously encrypted string
$decrypted = $dgcrypt->setCipherMethod('aes-256-cbc')->decrypt($encrypted);

// Output the decrypted string
echo $decrypted;
```

### Auto-Generating a Key:
```php
// Generate a secure random key
$generatedKey = $dgcrypt->generateKey();

// Output the generated key
echo $generatedKey; // Display the hexadecimal key
```

### Setting the Initialization Vector (IV):
```php
// Optionally, set a custom IV (12 bytes for GCM or ChaCha20, 16 bytes for CBC)
// If no IV is set, a secure random IV will be generated automatically
$dgcrypt->setIV();
```

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Author
Davod Mozafari - [Twitter](https://twitter.com/davodmozafari)
