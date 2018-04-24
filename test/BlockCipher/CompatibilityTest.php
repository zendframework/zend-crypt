<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\BlockCipher;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\BlockCipher;
use Zend\Math\Rand;

class CompatibilityTest extends TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
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
        try {
            $blockCipherMcrypt  = BlockCipher::factory('mcrypt', [ 'algo' => $algo ]);
            $blockCipherOpenssl = BlockCipher::factory('openssl', [ 'algo' => $algo ]);
        } catch (\Exception $e) {
            $this->markTestSkipped($e->getMessage());
        }

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
