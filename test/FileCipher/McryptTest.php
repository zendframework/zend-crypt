<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\FileCipher;

use Zend\Crypt\Symmetric\Mcrypt;
use Zend\Crypt\FileCipher;

class McryptTest extends AbstractFileCipherTest
{
    public function setUp()
    {
        try {
            $this->fileCipher = new FileCipher(new Mcrypt);
        } catch (Exception\RuntimeException $e) {
            $this->markTestSkipped('Mcrypt is not installed, I cannot execute ' . __CLASS__);
        }
        parent::setUp();
    }

    public function testSetCipher()
    {
        $cipher = new Mcrypt([
            'algo' => 'blowfish'
        ]);
        $this->fileCipher->setCipher($cipher);
        $this->assertInstanceOf('Zend\Crypt\Symmetric\SymmetricInterface', $this->fileCipher->getCipher());
        $this->assertEquals($cipher, $this->fileCipher->getCipher());
    }
}
