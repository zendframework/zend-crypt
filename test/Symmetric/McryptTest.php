<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use Interop\Container\ContainerInterface;
use Zend\Config\Config;
use Zend\Crypt\Symmetric\Exception;
use Zend\Crypt\Symmetric\Mcrypt;
use Zend\Crypt\Symmetric\Padding\NoPadding;
use Zend\Crypt\Symmetric\Padding\PKCS7;

/**
 * @group      Zend_Crypt
 */
class McryptTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Mcrypt
     */
    protected $mcrypt;
    /**
     * @var string
     */
    protected $key;
    /**
     * @var string
     */
    protected $salt;
    /**
     * @var string
     */
    protected $plaintext;

    public function setUp()
    {
        try {
            $this->mcrypt = new Mcrypt();
        } catch (Exception\RuntimeException $e) {
            $this->markTestSkipped('Mcrypt is not installed, I cannot execute the BlockCipherTest');
        }
        for ($i = 0; $i < 128; $i++) {
            $this->key .= chr(rand(0, 255));
            $this->salt .= chr(rand(0, 255));
        }
        $this->plaintext = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testConstructByParams()
    {
        $options = [
            'algorithm' => 'blowfish',
            'mode'      => 'cfb',
            'key'       => $this->key,
            'salt'      => $this->salt,
            'padding'   => 'pkcs7'
        ];
        $mcrypt  = new Mcrypt($options);
        $this->assertEquals($mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
        $this->assertEquals($mcrypt->getMode(), MCRYPT_MODE_CFB);
        $this->assertEquals($mcrypt->getKey(), substr($this->key, 0, $mcrypt->getKeySize()));
        $this->assertEquals($mcrypt->getSalt(), substr($this->salt, 0, $mcrypt->getSaltSize()));
        $this->assertInstanceOf(PKCS7::class, $mcrypt->getPadding());
    }

    public function testConstructByConfig()
    {
        $options = [
            'algorithm' => 'blowfish',
            'mode'      => 'cfb',
            'key'       => $this->key,
            'salt'      => $this->salt,
            'padding'   => 'pkcs7'
        ];
        $config  = new Config($options);
        $mcrypt  = new Mcrypt($config);
        $this->assertEquals($mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
        $this->assertEquals($mcrypt->getMode(), MCRYPT_MODE_CFB);
        $this->assertEquals($mcrypt->getKey(), substr($this->key, 0, $mcrypt->getKeySize()));
        $this->assertEquals($mcrypt->getSalt(), substr($this->salt, 0, $mcrypt->getSaltSize()));
        $this->assertInstanceOf(PKCS7::class, $mcrypt->getPadding());
    }

    public function testConstructWrongParam()
    {
        $options = 'test';
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The options parameter must be an array, a Zend\Config\Config object or a Traversable'
        );
        $mcrypt = new Mcrypt($options);
    }

    public function testSetAlgorithm()
    {
        $this->mcrypt->setAlgorithm(MCRYPT_BLOWFISH);
        $this->assertEquals($this->mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
    }

    public function testSetWrongAlgorithm()
    {
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The algorithm test is not supported by Zend\Crypt\Symmetric\Mcrypt'
        );
        $this->mcrypt->setAlgorithm('test');
    }

    public function testSetKey()
    {
        $result = $this->mcrypt->setKey($this->key);
        $this->assertInstanceOf(Mcrypt::class, $result);
        $this->assertEquals($result, $this->mcrypt);
    }

    public function testSetEmptyKey()
    {
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The key cannot be empty'
        );
        $result = $this->mcrypt->setKey('');
    }

    public function testSetShortKey()
    {
        foreach ($this->mcrypt->getSupportedAlgorithms() as $algo) {
            $this->mcrypt->setAlgorithm($algo);
            try {
                $result = $this->mcrypt->setKey('four');
            } catch (\Exception $ex) {
                $result = $ex;
            }
            if ($algo != 'blowfish') {
                $this->assertInstanceOf(
                    Exception\InvalidArgumentException::class,
                    $result
                );
            } else {
                $this->assertInstanceof(Mcrypt::class, $result);
            }
        }
    }

    public function testSetSalt()
    {
        $this->mcrypt->setSalt($this->salt);
        $this->assertEquals(
            substr($this->salt, 0, $this->mcrypt->getSaltSize()),
            $this->mcrypt->getSalt()
        );
        $this->assertEquals($this->salt, $this->mcrypt->getOriginalSalt());
    }

    /**
     * @expectedException Zend\Crypt\Symmetric\Exception\InvalidArgumentException
     */
    public function testShortSalt()
    {
        $this->mcrypt->setSalt('short');
    }

    public function testSetMode()
    {
        $this->mcrypt->setMode(MCRYPT_MODE_CFB);
        $this->assertEquals(MCRYPT_MODE_CFB, $this->mcrypt->getMode());
    }

    public function testSetWrongMode()
    {
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The mode xxx is not supported by Zend\Crypt\Symmetric\Mcrypt'
        );
        $this->mcrypt->setMode('xxx');
    }

    public function testEncryptDecrypt()
    {
        $this->mcrypt->setKey($this->key);
        $this->mcrypt->setPadding(new PKCS7());
        $this->mcrypt->setSalt($this->salt);
        foreach ($this->mcrypt->getSupportedAlgorithms() as $algo) {
            foreach ($this->mcrypt->getSupportedModes() as $mode) {
                $this->mcrypt->setAlgorithm($algo);
                $this->mcrypt->setMode($mode);
                $encrypted = $this->mcrypt->encrypt($this->plaintext);
                $this->assertNotEmpty($encrypted);
                $decrypted = $this->mcrypt->decrypt($encrypted);
                $this->assertNotFalse($decrypted);
                $this->assertEquals($this->plaintext, $decrypted);
            }
        }
    }

    public function testEncryptWithoutKey()
    {
        $this->setExpectedException('Zend\Crypt\Symmetric\Exception\InvalidArgumentException');
        $ciphertext = $this->mcrypt->encrypt('test');
    }

    public function testEncryptEmptyData()
    {
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The data to encrypt cannot be empty'
        );
        $ciphertext = $this->mcrypt->encrypt('');
    }

    public function testEncryptWihoutSalt()
    {
        $this->mcrypt->setKey($this->key);
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The salt (IV) cannot be empty'
        );
        $ciphertext = $this->mcrypt->encrypt($this->plaintext);
    }

    public function testDecryptEmptyData()
    {
        $this->setExpectedException(
            Exception\InvalidArgumentException::class,
            'The data to decrypt cannot be empty'
        );
        $ciphertext = $this->mcrypt->decrypt('');
    }

    public function testDecryptWithoutKey()
    {
        $this->setExpectedException(Exception\InvalidArgumentException::class);
        $this->mcrypt->decrypt($this->plaintext);
    }

    public function testSetOptions()
    {
        $options = [
            'algo'    => 'blowfish',
            'mode'    =>  MCRYPT_MODE_CFB,
            'key'     => 'test',
            'iv'      => '12345678',
            'padding' => 'nopadding'
        ];
        $this->mcrypt->setOptions($options);

        $this->assertEquals($options['algo'], $this->mcrypt->getAlgorithm());
        $this->assertEquals($options['mode'], $this->mcrypt->getMode());
        $this->assertEquals($options['key'], $this->mcrypt->getKey());
        $this->assertEquals($options['iv'], $this->mcrypt->getSalt());
        $this->assertInstanceOf(NoPadding::class, $this->mcrypt->getPadding());
    }

    public function testSetPaddingPluginManager()
    {
        $this->mcrypt->setPaddingPluginManager(
            $this->getMockBuilder(ContainerInterface::class)->getMock()
        );
        $this->assertInstanceOf(ContainerInterface::class, $this->mcrypt->getPaddingPluginManager());
    }
}
