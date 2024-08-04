<?php

use PHPUnit\Framework\TestCase;
use Dgcrypt\Dgcrypt;

class DgcryptTest extends TestCase
{
    private $key;
    private $originalText;

    protected function setUp(): void
    {
        $this->key = '12345678901234567890123456789012';
        $this->originalText = 'Hello, World!';
    }

    public function testEncryptDecryptAES256CBC()
    {
        $dgcrypt = new Dgcrypt('aes-256-cbc');
        $dgcrypt->setKey($this->key);

        $encrypted = $dgcrypt->encrypt($this->originalText);
        $decrypted = $dgcrypt->decrypt($encrypted);

        $this->assertEquals($this->originalText, $decrypted);
    }

    public function testEncryptDecryptAES256GCM()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $dgcrypt->setKey($this->key);

        $encrypted = $dgcrypt->encrypt($this->originalText);
        $decrypted = $dgcrypt->decrypt($encrypted);

        $this->assertEquals($this->originalText, $decrypted);
    }

    public function testEncryptDecryptChaCha20Poly1305()
    {
        $dgcrypt = new Dgcrypt('chacha20-poly1305');
        $dgcrypt->setKey($this->key);

        $encrypted = $dgcrypt->encrypt($this->originalText);
        $decrypted = $dgcrypt->decrypt($encrypted);

        $this->assertEquals($this->originalText, $decrypted);
    }

    public function testGenerateKey()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $key = $dgcrypt->generateKey();

        $this->assertEquals(32, strlen($key));
    }

    public function testSetIV()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $dgcrypt->setKey($this->key);
        $dgcrypt->setIV();

        $encrypted = $dgcrypt->encrypt($this->originalText);
        $this->assertNotNull($encrypted);
    }

    public function testEncryptDecryptWithCustomIV()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $dgcrypt->setKey($this->key);
        $customIV = '123456789012'; // 12 bytes for GCM
        $dgcrypt->setIV($customIV);

        $encrypted = $dgcrypt->encrypt($this->originalText);
        $decrypted = $dgcrypt->decrypt($encrypted);

        $this->assertEquals($this->originalText, $decrypted);
    }

    public function testEncryptDecryptWithDifferentKeys()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $dgcrypt->setKey($this->key);

        $encrypted = $dgcrypt->encrypt($this->originalText);

        $differentKey = '09876543210987654321098765432109';
        $dgcrypt->setKey($differentKey);

        $this->expectException(\Exception::class);
        $dgcrypt->decrypt($encrypted);
    }

    public function testEncryptDecryptWithModifiedData()
    {
        $dgcrypt = new Dgcrypt('aes-256-gcm');
        $dgcrypt->setKey($this->key);

        $encrypted = $dgcrypt->encrypt($this->originalText);

        // Modify encrypted data
        $decodedString = base64_decode($encrypted);
        $decodedString[10] = ($decodedString[10] === 'a') ? 'b' : 'a';
        $modifiedEncrypted = base64_encode($decodedString);

        $this->expectException(\Exception::class);
        $dgcrypt->decrypt($modifiedEncrypted);
    }
}
