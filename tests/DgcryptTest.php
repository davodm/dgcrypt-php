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
}
