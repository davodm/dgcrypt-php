# Dgcrypt

Dgcrypt is a simple PHP library for encryption and decryption using **AES-256-CBC**. It is designed to securely encrypt data on the backend, which can then be easily decrypted on the client side, such as on Android and iOS devices. This ensures that the data remains secure during transmission and cannot be easily cracked in between.

## Platform Compatibility
The Dgcrypt library is designed to work seamlessly across multiple platforms. You can find corresponding libraries for the following platforms:

- **Android**: [Dgcrypt-Android](https://github.com/davodm/dgcrypt-android)
- **Node.js**: [Dgcrypt-Node](https://github.com/davodm/dgcrypt-node)

These libraries allow you to easily decrypt data that was encrypted on the backend using this PHP library, ensuring secure communication between your backend and client applications.

## Installation

You can install the package via Composer:

```bash
composer require davodm/dgcrypt-php
```

## Usage
#### Encrypting Data on the Backend:

```php
use Dgcrypt\Dgcrypt;

// Initialize the Dgcrypt class
$dgcrypt = new Dgcrypt();

// Set a 32-character secret key
$dgcrypt->setKey('your-32-character-long-key');

// Encrypt a string
$plainText = 'Hello, World!';
$encrypted = $dgcrypt->encrypt($plainText);

// Output the encrypted string
echo $encrypted;
```

#### Decrypting Data on the Backend:
```php
use Dgcrypt\Dgcrypt;

// Initialize the Dgcrypt class
$dgcrypt = new Dgcrypt();

// Set the same 32-character secret key used for encryption
$dgcrypt->setKey('your-32-character-long-key');

// Decrypt the previously encrypted string
$decrypted = $dgcrypt->decrypt($encrypted);

// Output the decrypted string
echo $decrypted;
```

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Author
Davod Mozafari - [Twitter](https://twitter.com/davodmozafari)

