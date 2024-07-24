<?php

use PHPUnit\Framework\TestCase;
use Dgcrypt\Dgcrypt;

class DgcryptTest extends TestCase
{
    public function testEncryptDecrypt()
    {
        $dgcrypt = new Dgcrypt();
        $dgcrypt->setKey('12345678901234567890123456789012');
        
        $originalText = 'Hello, World!';
        $encrypted = $dgcrypt->encrypt($originalText);
        $decrypted = $dgcrypt->decrypt($encrypted);
        
        $this->assertEquals($originalText, $decrypted);
    }
}
