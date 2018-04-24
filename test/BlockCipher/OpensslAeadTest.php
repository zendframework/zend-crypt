<?php
/**
 * @link      http://github.com/zendframework/zend-crypt for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\BlockCipher;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\BlockCipher;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Math\Rand;

class OpensslAeadTest extends TestCase
{
    public function setUp()
    {
        $openssl = new Openssl();
        if (! $openssl->isAuthEncAvailable()) {
            $this->markTestSkipped('Authenticated encryption is not available on this platform');
        }
        $this->blockCipher = new BlockCipher($openssl);
    }

    public function getAuthEncryptionMode()
    {
        return [
            [ 'gcm' ],
            [ 'ccm' ]
        ];
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testEncryptDecrypt($mode)
    {
        $this->blockCipher->getCipher()->setMode($mode);
        $this->blockCipher->setKey('test');
        $plaintext = Rand::getBytes(1024);
        $ciphertext = $this->blockCipher->encrypt($plaintext);
        $this->assertEquals($plaintext, $this->blockCipher->decrypt($ciphertext));
    }
}
