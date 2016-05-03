<?php
namespace ZendTest\Crypt\BlockCipher;

use Zend\Crypt\Symmetric;
use Zend\Crypt\BlockCipher;

class MCryptTest extends AbstractBlockCipherTest
{
    public function setUp()
    {
        try {
            $this->cipher = new Symmetric\Mcrypt([
                'algorithm' => 'aes',
                'mode'      => 'cbc',
                'padding'   => 'pkcs7'
            ]);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped('Mcrypt is not installed, I cannot execute the BlockCipherTest');
        }
        parent::setUp();
    }

    public function testSetCipher()
    {
        $mcrypt = new Symmetric\Mcrypt();
        $result = $this->blockCipher->setCipher($this->cipher);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals($this->cipher, $this->blockCipher->getCipher());
    }

    public function testFactory()
    {
        $this->blockCipher = BlockCipher::factory('mcrypt', ['algo' => 'blowfish']);
        $this->assertInstanceOf(Symmetric\Mcrypt::class, $this->blockCipher->getCipher());
        $this->assertEquals('blowfish', $this->blockCipher->getCipher()->getAlgorithm());
    }

    public function testFactoryEmptyOptions()
    {
        $this->blockCipher = BlockCipher::factory('mcrypt');
        $this->assertInstanceOf(Symmetric\Mcrypt::class, $this->blockCipher->getCipher());
    }
}
