<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use PHPUnit\Framework\TestCase;
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
            [ 'des' ]
        ];
    }

    /**
     * @dataProvider getAlgos
     */
    public function testMcryptAndOpenssl($algo)
    {
        $key     = Rand::getBytes(56);
        $iv      = Rand::getBytes(16);
        $mcrypt  = new Mcrypt([
            'algo' => $algo,
            'key'  => $key,
            'iv'   => $iv
        ]);
        $openssl = new Openssl([
            'algo' => $algo,
            'key'  => $key,
            'iv'   => $iv
        ]);

        $plaintext = Rand::getBytes(1024);

        $encrypted = $mcrypt->encrypt($plaintext);
        $this->assertEquals($plaintext, $openssl->decrypt($encrypted));

        $encrypted = $openssl->encrypt($plaintext);
        $this->assertEquals($plaintext, $mcrypt->decrypt($encrypted));
    }
}
