<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\BlockCipher;

use PHPUnit_Framework_TestCase as TestCase;
use Zend\Crypt\BlockCipher;
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
        $blockCipherMcrypt  = BlockCipher::factory('mcrypt', [ 'algo' => $algo ]);
        $blockCipherOpenssl = BlockCipher::factory('openssl', [ 'algo' => $algo ]);

        $key       = Rand::getBytes(32);
        $plaintext = Rand::getBytes(1024);
        $blockCipherMcrypt->setKey($key);
        $blockCipherOpenssl->setKey($key);

        $encrypted = $blockCipherMcrypt->encrypt($plaintext);
        $this->assertEquals($plaintext, $blockCipherOpenssl->decrypt($encrypted));

        $encrypted = $blockCipherOpenssl->encrypt($plaintext);
        $this->assertEquals($plaintext, $blockCipherMcrypt->decrypt($encrypted));
    }
}
