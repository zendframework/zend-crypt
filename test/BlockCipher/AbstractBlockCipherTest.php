<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\BlockCipher;

use Interop\Container\ContainerInterface;
use PHPUnit\Framework\TestCase;
use Zend\Crypt\BlockCipher;
use Zend\Crypt\Exception;
use Zend\Crypt\Symmetric;

abstract class AbstractBlockCipherTest extends TestCase
{
    /**
     * @var Symmetric\SymmetricInterface
     */
    protected $cipher;

    /**
     * @var BlockCipher
     */
    protected $blockCipher;

    /**
     * @var string
     */
    protected $plaintext;

    public function setUp()
    {
        $this->assertInstanceOf(
            Symmetric\SymmetricInterface::class,
            $this->cipher,
            'Symmetric adapter instance is needed for tests'
        );
        $this->blockCipher = new BlockCipher($this->cipher);
        $this->plaintext = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testSetKey()
    {
        $result = $this->blockCipher->setKey('test');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('test', $this->blockCipher->getKey());
    }

    public function testSetEmptyKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setKey('');
    }

    public function testSetSalt()
    {
        $salt = str_repeat('a', $this->blockCipher->getCipher()->getSaltSize() + 2);
        $result = $this->blockCipher->setSalt($salt);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals(
            substr($salt, 0, $this->blockCipher->getCipher()->getSaltSize()),
            $this->blockCipher->getSalt()
        );
        $this->assertEquals($salt, $this->blockCipher->getOriginalSalt());
    }

    public function testSetWrongSalt()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSalt('x');
    }

    public function testSetAlgorithm()
    {
        $result = $this->blockCipher->setCipherAlgorithm('blowfish');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('blowfish', $this->blockCipher->getCipherAlgorithm());
    }

    public function testSetAlgorithmFail()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The algorithm unknown is not supported by %s',
            get_class($this->cipher)
        ));
        $result = $this->blockCipher->setCipherAlgorithm('unknown');
    }

    public function testSetHashAlgorithm()
    {
        $result = $this->blockCipher->setHashAlgorithm('sha1');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('sha1', $this->blockCipher->getHashAlgorithm());
    }

    public function testSetUnsupportedHashAlgorithm()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setHashAlgorithm('foo');
    }

    public function testSetPbkdf2HashAlgorithm()
    {
        $result = $this->blockCipher->setPbkdf2HashAlgorithm('sha1');
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals('sha1', $this->blockCipher->getPbkdf2HashAlgorithm());
    }

    public function testSetUnsupportedPbkdf2HashAlgorithm()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setPbkdf2HashAlgorithm('foo');
    }

    public function testSetKeyIteration()
    {
        $result = $this->blockCipher->setKeyIteration(1000);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals(1000, $this->blockCipher->getKeyIteration());
    }

    public function testEncryptWithoutData()
    {
        $plaintext = '';
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to encrypt cannot be empty');
        $this->blockCipher->encrypt($plaintext);
    }

    public function testEncryptErrorKey()
    {
        $plaintext = 'test';
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('No key specified for the encryption');
        $this->blockCipher->encrypt($plaintext);
    }

    public function testEncryptDecrypt()
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            $this->blockCipher->setCipherAlgorithm($algo);
            $encrypted = $this->blockCipher->encrypt($this->plaintext);
            $this->assertNotEmpty($encrypted);
            $decrypted = $this->blockCipher->decrypt($encrypted);
            $this->assertEquals($decrypted, $this->plaintext);
        }
    }

    public function testEncryptDecryptUsingBinary()
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        $this->blockCipher->setBinaryOutput(true);
        $this->assertTrue($this->blockCipher->getBinaryOutput());

        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            $this->blockCipher->setCipherAlgorithm($algo);
            $encrypted = $this->blockCipher->encrypt($this->plaintext);
            $this->assertNotEmpty($encrypted);
            $decrypted = $this->blockCipher->decrypt($encrypted);
            $this->assertEquals($decrypted, $this->plaintext);
        }
    }

    public function zeroValuesProvider()
    {
        return [
            '"0"'   => [0],
            '"0.0"' => [0.0],
            '"0"'   => ['0'],
        ];
    }

    /**
     * @dataProvider zeroValuesProvider
     */
    public function testEncryptDecryptUsingZero($value)
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        foreach ($this->blockCipher->getCipherSupportedAlgorithms() as $algo) {
            $this->blockCipher->setCipherAlgorithm($algo);

            $encrypted = $this->blockCipher->encrypt($value);
            $this->assertNotEmpty($encrypted);
            $decrypted = $this->blockCipher->decrypt($encrypted);
            $this->assertEquals($value, $decrypted);
        }
    }

    public function testDecryptNotString()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->decrypt([ 'foo' ]);
    }

    public function testDecryptEmptyString()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->decrypt('');
    }

    public function testDecyptWihoutKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->decrypt('encrypted data');
    }

    public function testDecryptAuthFail()
    {
        $this->blockCipher->setKey('test');
        $this->blockCipher->setKeyIteration(1000);
        $encrypted = $this->blockCipher->encrypt($this->plaintext);
        $this->assertNotEmpty($encrypted);
        // tamper the encrypted data
        $encrypted = substr($encrypted, -1);
        $decrypted = $this->blockCipher->decrypt($encrypted);
        $this->assertFalse($decrypted);
    }

    public function testSetSymmetricPluginManager()
    {
        $old = $this->blockCipher->getSymmetricPluginManager();

        $this->blockCipher->setSymmetricPluginManager(
            $this->getMockBuilder(ContainerInterface::class)->getMock()
        );
        $this->assertInstanceOf(ContainerInterface::class, $this->blockCipher->getSymmetricPluginManager());

        $this->blockCipher->setSymmetricPluginManager($old);
    }

    public function testFactoryWithWrongAdapter()
    {
        $this->expectException(Exception\RuntimeException::class);
        $this->blockCipher = BlockCipher::factory('foo');
    }

    public function testSetWrongSymmetricPluginManager()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSymmetricPluginManager(stdClass::class);
    }

    public function testSetNotExistingSymmetricPluginManager()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->blockCipher->setSymmetricPluginManager('Foo');
    }
}
