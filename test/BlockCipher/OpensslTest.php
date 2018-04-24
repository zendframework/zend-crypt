<?php
/**
 * @link      http://github.com/zendframework/zend-crypt for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\BlockCipher;

use Zend\Crypt\BlockCipher;
use Zend\Crypt\Symmetric;

class OpensslTest extends AbstractBlockCipherTest
{
    public function setUp()
    {
        try {
            $this->cipher = new Symmetric\Openssl([
                'algorithm' => 'aes',
                'mode'      => 'cbc',
                'padding'   => 'pkcs7'
            ]);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testSetCipher()
    {
        $mcrypt = new Symmetric\Openssl();
        $result = $this->blockCipher->setCipher($this->cipher);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals($this->cipher, $this->blockCipher->getCipher());
    }

    public function testFactory()
    {
        $this->blockCipher = BlockCipher::factory('openssl', [ 'algo' => 'blowfish' ]);
        $this->assertInstanceOf(Symmetric\Openssl::class, $this->blockCipher->getCipher());
        $this->assertEquals('blowfish', $this->blockCipher->getCipher()->getAlgorithm());
    }

    public function testFactoryEmptyOptions()
    {
        $this->blockCipher = BlockCipher::factory('openssl');
        $this->assertInstanceOf(Symmetric\Openssl::class, $this->blockCipher->getCipher());
    }
}
