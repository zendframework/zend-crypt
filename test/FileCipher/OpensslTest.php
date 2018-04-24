<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\FileCipher;

use Zend\Crypt\FileCipher;
use Zend\Crypt\Symmetric;
use Zend\Crypt\Symmetric\Openssl;

class OpensslTest extends AbstractFileCipherTest
{
    public function setUp()
    {
        try {
            $this->fileCipher = new FileCipher(new Openssl);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testDefaultCipher()
    {
        $fileCipher = new FileCipher();
        $this->assertInstanceOf(Openssl::class, $fileCipher->getCipher());
    }

    public function testSetCipher()
    {
        $cipher = new Openssl([
            'algo' => 'blowfish'
        ]);
        $this->fileCipher->setCipher($cipher);
        $this->assertInstanceOf('Zend\Crypt\Symmetric\SymmetricInterface', $this->fileCipher->getCipher());
        $this->assertEquals($cipher, $this->fileCipher->getCipher());
    }
}
