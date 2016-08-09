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

    public function testEncryptDecryptWithOneStringKey()
    {
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        // Get the public and private key as string (PEM format)
        $details   = openssl_pkey_get_details($opensslKeys);
        $publicKey = $details['key'];
        openssl_pkey_export($opensslKeys, $privateKey);

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleStringKeys()
    {
        $publicKeys  = [];
        $privateKeys = [];
        for ($id = 0; $id < 5; $id++) {
            $opensslKeys = openssl_pkey_new([
                "private_key_bits" => 1024,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ]);
            $details = openssl_pkey_get_details($opensslKeys);
            $publicKeys[$id] = $details['key'];
            openssl_pkey_export($opensslKeys, $privateKeys[$id]);
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    public function testEncryptDecryptWithOneObjectKey()
    {
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        // Get the public and private key as Zend\Crypt\PublicKey\Rsa objects
        $details   = openssl_pkey_get_details($opensslKeys);
        $publicKey = new Rsa\PublicKey($details['key']);
        openssl_pkey_export($opensslKeys, $privateKey);
        $privateKey = new Rsa\PrivateKey($privateKey);

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleObjectKeys()
    {
        $publicKeys  = [];
        $privateKeys = [];
        for ($id = 0; $id < 5; $id++) {
            $opensslKeys = openssl_pkey_new([
                "private_key_bits" => 1024,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ]);
            $details = openssl_pkey_get_details($opensslKeys);
            $publicKeys[$id] = new Rsa\PublicKey($details['key']);
            openssl_pkey_export($opensslKeys, $privateKey);
            $privateKeys[$id] = new Rsa\PrivateKey($privateKey);
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    /**
     * @expectedException Zend\Crypt\Exception\RuntimeException
     */
    public function testFailToDecryptWithOneKey()
    {
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        // Get the public and private key as string (PEM format)
        $details   = openssl_pkey_get_details($opensslKeys);
        $publicKey = $details['key'];

        // Generate a new public/private key
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($opensslKeys, $privateKey);

        // encrypt using a single key
        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        // try to decrypt using a different private key throws an exception
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
    }

    /**
     * @expectedException Zend\Crypt\Exception\RuntimeException
     */
    public function testFailToDecryptWithMultipleKeys()
    {
        $publicKeys  = [];
        $privateKeys = [];
        for ($id = 0; $id < 5; $id++) {
            $opensslKeys = openssl_pkey_new([
                "private_key_bits" => 1024,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ]);
            $details = openssl_pkey_get_details($opensslKeys);
            $publicKeys[$id] = $details['key'];
            openssl_pkey_export($opensslKeys, $privateKeys[$id]);
        }

        // Generate a new public/private key
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($opensslKeys, $privateKey);

        // encrypt using a keyrings
        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        // try to decrypt using a different private key throws an exception
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys, $id);
    }

    /**
     * @expectedException Zend\Crypt\Exception\RuntimeException
     */
    public function testFailToEncryptUsingPrivateKey()
    {
        $opensslKeys = openssl_pkey_new([
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($opensslKeys, $privateKey);
        $privateKey = new Rsa\PrivateKey($privateKey);

        // encrypt using a PrivateKey object throws an exception
        $encrypted = $this->hybrid->encrypt('test', $privateKey);
    }
}
