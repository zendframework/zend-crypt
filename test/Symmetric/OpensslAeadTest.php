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
use Zend\Crypt\Symmetric\Exception\InvalidArgumentException;
use Zend\Crypt\Symmetric\Exception\RuntimeException;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Math\Rand;

/**
 *
 * This is a set of unit tests for OpenSSL Authenticated Encrypt with Associated Data (AEAD)
 * support from PHP 7.1+
 */
class OpensslAeadTest extends TestCase
{
    /**
     * @var Openssl
     */
    private $crypt;

    public function setUp()
    {
        $this->crypt = new Openssl();

        if (! $this->crypt->isAuthEncAvailable()) {
            $this->markTestSkipped('Authenticated encryption is not available on this platform');
        }
    }

    public function testConstructByParams()
    {
        $params = [
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 'foo@bar.com',
            'tag_size' => 14
        ];
        $crypt = new Openssl($params);

        $this->assertEquals($params['algo'], $crypt->getAlgorithm());
        $this->assertEquals($params['mode'], $crypt->getMode());
        $this->assertEquals($params['aad'], $crypt->getAad());
        $this->assertEquals($params['tag_size'], $crypt->getTagSize());
    }

    public function testRejectsNonStringAadMode()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The provided $aad must be a string, integer given');

        new Openssl([
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 123, // invalid, on purpose
            'tag_size' => 14,
        ]);
    }

    public function testRejectsNonIntegerTagSize()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The provided $size must be an integer, double given');

        new Openssl([
            'algo'     => 'aes',
            'mode'     => 'gcm',
            'aad'      => 'foo@bar.com',
            'tag_size' => 14.5, // invalid, on purpose
        ]);
    }

    public function testSetGetAad()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setAad('foo@bar.com');
        $this->assertEquals('foo@bar.com', $this->crypt->getAad());
    }

    public function testSetAadException()
    {
        $this->crypt->setMode('cbc');

        $this->expectException(RuntimeException::class);
        $this->crypt->setAad('foo@bar.com');
    }

    public function testSetGetGcmTagSize()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setTagSize(10);
        $this->assertEquals(10, $this->crypt->getTagSize());
    }

    public function testSetGetCcmTagSize()
    {
        $this->crypt->setMode('ccm');
        $this->crypt->setTagSize(28);
        $this->assertEquals(28, $this->crypt->getTagSize());
    }

    public function testSetTagSizeException()
    {
        $this->crypt->setMode('cbc');

        $this->expectException(RuntimeException::class);
        $this->crypt->setTagSize(10);
    }

    public function testSetInvalidGcmTagSize()
    {
        $this->crypt->setMode('gcm');

        $this->expectException(InvalidArgumentException::class);
        $this->crypt->setTagSize(18); // gcm supports tag size between 4 and 16
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
    public function testAuthenticatedEncryption($mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);
        $tag = $this->crypt->getTag();

        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($tag, '8bit'));
        $this->assertEquals(mb_substr($encrypt, 0, $this->crypt->getTagSize(), '8bit'), $tag);

        $decrypt = $this->crypt->decrypt($encrypt);
        $tag2 = $this->crypt->getTag();
        $this->assertEquals($tag, $tag2);
        $this->assertEquals($plaintext, $decrypt);
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticationError($mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);

        // Alter the encrypted message
        $i = rand(0, mb_strlen($encrypt, '8bit') - 1);
        $encrypt[$i] = $encrypt[$i] ^ chr(1);

        $this->expectException(RuntimeException::class);
        $this->crypt->decrypt($encrypt);
    }

    public function testGcmEncryptWithTagSize()
    {
        $this->crypt->setMode('gcm');
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setTagSize(14);

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);
        $this->assertEquals(14, $this->crypt->getTagSize());
        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($this->crypt->getTag(), '8bit'));
    }

    public function testCcmEncryptWithTagSize()
    {
        $this->crypt->setMode('ccm');
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setTagSize(24);

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);
        $this->assertEquals(24, $this->crypt->getTagSize());
        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($this->crypt->getTag(), '8bit'));
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticatedEncryptionWithAdditionalData($mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setAad('foo@bar.com');

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);
        $tag = $this->crypt->getTag();

        $this->assertEquals($this->crypt->getTagSize(), mb_strlen($tag, '8bit'));
        $this->assertEquals(mb_substr($encrypt, 0, $this->crypt->getTagSize(), '8bit'), $tag);

        $decrypt = $this->crypt->decrypt($encrypt);
        $tag2 = $this->crypt->getTag();
        $this->assertEquals($tag, $tag2);
        $this->assertEquals($plaintext, $decrypt);
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testAuthenticationErrorOnAdditionalData($mode)
    {
        $this->crypt->setMode($mode);
        $this->crypt->setKey(random_bytes($this->crypt->getKeySize()));
        $this->crypt->setSalt(random_bytes($this->crypt->getSaltSize()));
        $this->crypt->setAad('foo@bar.com');

        $plaintext = Rand::getBytes(1024);
        $encrypt = $this->crypt->encrypt($plaintext);

        // Alter the additional authentication data
        $this->crypt->setAad('foo@baz.com');

        $this->expectException(RuntimeException::class);

        $this->crypt->decrypt($encrypt);
    }
}
