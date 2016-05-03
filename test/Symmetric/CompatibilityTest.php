<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use PHPUnit_Framework_TestCase as TestCase;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Crypt\Symmetric\Mcrypt;
use Zend\Math\Rand;

class CompatibilityTest extends TestCase
{
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
