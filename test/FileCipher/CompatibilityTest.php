<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\FileCipher;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\FileCipher;
use Zend\Crypt\Symmetric\Mcrypt;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Math\Rand;

class CompatibilityTest extends TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
        }
        if (! extension_loaded('mcrypt') || ! extension_loaded('openssl')) {
            $this->markTestSkipped(
                sprintf("I cannot execute %s without Mcrypt and OpenSSL installed", __CLASS__)
            );
        }
    }

    public function getAlgos()
    {
        return [
            [ 'aes' ],
            [ 'blowfish' ],
            [ 'des' ],
        ];
    }

    /**
     * @dataProvider getAlgos
     */
    public function testMcryptAndOpenssl($algo)
    {
        $fileCipherMcrypt  = new FileCipher(new Mcrypt);
        $fileCipherOpenssl = new FileCipher(new Openssl);

        $key = Rand::getBytes(16);
        $fileCipherMcrypt->setKey($key);
        $fileCipherOpenssl->setKey($key);

        $tmpIn   = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('zend-crypt-test-in-');
        $tmpOut  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('zend-crypt-test-out-');
        $tmpOut2 = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('zend-crypt-test-out-');
        $plaintext = Rand::getBytes(1048576); // 1 Mb
        file_put_contents($tmpIn, $plaintext);

        $fileCipherMcrypt->encrypt($tmpIn, $tmpOut);
        $fileCipherOpenssl->decrypt($tmpOut, $tmpOut2);
        $this->assertEquals($plaintext, file_get_contents($tmpOut2));

        unlink($tmpOut2);
        unlink($tmpOut);

        $fileCipherOpenssl->encrypt($tmpIn, $tmpOut);
        $fileCipherMcrypt->decrypt($tmpOut, $tmpOut2);
        $this->assertEquals($plaintext, file_get_contents($tmpOut2));

        unlink($tmpIn);
        unlink($tmpOut);
        unlink($tmpOut2);
    }
}
