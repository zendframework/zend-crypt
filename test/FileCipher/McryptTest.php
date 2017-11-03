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
use Zend\Crypt\Symmetric\Mcrypt;

class McryptTest extends AbstractFileCipherTest
{
    public function setUp()
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
        }
        try {
            $this->fileCipher = new FileCipher(new Mcrypt);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
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
