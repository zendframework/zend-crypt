<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt;

use Zend\Crypt\Hybrid;
use Zend\Crypt\BlockCipher;
use Zend\Crypt\PublicKey\Rsa;

/**
 * @group      Zend_Crypt
 */
class HybridTest extends \PHPUnit_Framework_TestCase
{
    protected $hybrid;

    public function setUp()
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('The OpenSSL extension is required');
        }
        $this->hybrid = new Hybrid();
    }

    public function testConstructor()
    {
        $hybrid = new Hybrid();
        $this->assertInstanceOf(Hybrid::class, $hybrid);
    }

    public function testGetDefaultBlockCipherInstance()
    {
        $bCipher = $this->hybrid->getBlockCipherInstance();
        $this->assertInstanceOf(BlockCipher::class, $bCipher);
    }

    public function testGetDefaultRsaInstance()
    {
        $rsa = $this->hybrid->getRsaInstance();
        $this->assertInstanceOf(Rsa::class, $rsa);
    }

    public function testEncryptDecryptWithOneKey()
    {
        $keys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        // Get the public and private key as string (PEM format)
        $details   = openssl_pkey_get_details($keys);
        $publicKey = $details['key'];
        openssl_pkey_export($keys, $privateKey);

        $result = $this->hybrid->encrypt('test', $publicKey);
        $this->assertEquals('test', $this->hybrid->decrypt($result, $privateKey));
    }

    public function testEncryptWithMultipleKeys()
    {
    }
}
