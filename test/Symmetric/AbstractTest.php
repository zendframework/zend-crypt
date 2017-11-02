<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use ArrayObject;
use Interop\Container\ContainerInterface;
use PHPUnit\Framework\TestCase;
use Zend\Crypt\Symmetric\Exception;
use Zend\Crypt\Symmetric\Padding\NoPadding;
use Zend\Crypt\Symmetric\Padding\PKCS7;
use Zend\Math\Rand;

/**
 * @group      Zend_Crypt
 */
abstract class AbstractTest extends TestCase
{
    /**
     * @var string
     */
    protected $adapterClass = '';
    /**
     * @var object
     */
    protected $crypt;
    /**
     * @var string
     */
    protected $plaintext;
    /**
     * @var string
     */
    protected $default_algo;
    /**
     * @var string
     */
    protected $default_mode;
    /**
     * @var string
     */
    protected $default_padding;

    public function setUp()
    {
        try {
            $this->crypt = new $this->adapterClass;
        } catch (Exception\RuntimeException $e) {
            $this->markTestSkipped(
                sprintf("%s is not installed, I cannot execute %s", $this->adapterClass, static::class)
            );
        }
        $this->plaintext = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testConstructByParams()
    {
        $key = $this->generateKey();
        $iv  = $this->generateSalt();
        $options = [
            'algorithm' => $this->default_algo,
            'mode'      => $this->default_mode,
            'key'       => $key,
            'salt'      => $iv,
            'padding'   => $this->default_padding
        ];
        $crypt  = new $this->adapterClass($options);
        $this->assertEquals($crypt->getAlgorithm(), $options['algorithm']);
        $this->assertEquals($crypt->getMode(), $options['mode']);
        $this->assertEquals($crypt->getKey(), mb_substr($key, 0, $crypt->getKeySize(), '8bit'));
        $this->assertEquals($crypt->getSalt(), mb_substr($iv, 0, $crypt->getSaltSize(), '8bit'));
        $this->assertInstanceOf(PKCS7::class, $crypt->getPadding());
    }

    /**
     * This test uses ArrayObject to simulate a Zend\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig()
    {
        $key = $this->generateKey();
        $iv  = $this->generateSalt();
        $options = [
            'algorithm' => $this->default_algo,
            'mode'      => $this->default_mode,
            'key'       => $key,
            'salt'      => $iv,
            'padding'   => $this->default_padding
        ];
        $config  = new ArrayObject($options);
        $crypt  = new $this->adapterClass($config);
        $this->assertEquals($crypt->getAlgorithm(), $options['algorithm']);
        $this->assertEquals($crypt->getMode(), $options['mode']);
        $this->assertEquals($crypt->getKey(), mb_substr($key, 0, $crypt->getKeySize(), '8bit'));
        $this->assertEquals($crypt->getSalt(), mb_substr($iv, 0, $crypt->getSaltSize(), '8bit'));
        $this->assertInstanceOf(PKCS7::class, $crypt->getPadding());
    }

    public function testConstructWrongParam()
    {
        $options = 'test';
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The options parameter must be an array or a Traversable');
        new $this->adapterClass($options);
    }

    public function testSetAlgorithm()
    {
        $this->crypt->setAlgorithm($this->default_algo);
        $this->assertEquals($this->crypt->getAlgorithm(), $this->default_algo);
    }

    public function testSetWrongAlgorithm()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The algorithm test is not supported by %s',
            $this->adapterClass
        ));
        $this->crypt->setAlgorithm('test');
    }

    public function testSetKey()
    {
        $key = $this->generateKey();
        $result = $this->crypt->setKey($key);
        $this->assertInstanceOf($this->adapterClass, $result);
        $this->assertEquals($result, $this->crypt);
        $this->assertEquals($key, $this->crypt->getKey());
    }

    public function testSetEmptyKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key cannot be empty');
        $this->crypt->setKey('');
    }

    public function testSetShortKey()
    {
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            $this->crypt->setAlgorithm($algo);
            try {
                $result = $this->crypt->setKey('four');
            } catch (\Exception $ex) {
                $this->assertInstanceOf(
                    Exception\InvalidArgumentException::class,
                    $ex
                );
            }
        }
    }

    public function testSetSalt()
    {
        $iv = $this->generateSalt() . $this->generateSalt();
        $this->crypt->setSalt($iv);
        $this->assertEquals(
            mb_substr($iv, 0, mb_strlen($iv, '8bit') / 2, '8bit'),
            $this->crypt->getSalt()
        );
        $this->assertEquals($iv, $this->crypt->getOriginalSalt());
    }

    public function testShortSalt()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setSalt('short');
    }

    public function testSetMode()
    {
        $this->crypt->setMode($this->default_mode);
        $this->assertEquals($this->default_mode, $this->crypt->getMode());
    }

    public function testSetWrongMode()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The mode xxx is not supported by %s',
            $this->crypt->getAlgorithm()
        ));
        $this->crypt->setMode('xxx');
    }

    public function testEncryptDecrypt()
    {
        $this->crypt->setPadding(new PKCS7());
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            foreach ($this->crypt->getSupportedModes() as $mode) {
                $this->crypt->setAlgorithm($algo);
                try {
                    $this->crypt->setMode($mode);
                } catch (\Exception $e) {
                    // Continue if the encryption mode is not supported for the algorithm
                    continue;
                }
                $this->crypt->setKey($this->generateKey());
                if ($this->crypt->getSaltSize() > 0) {
                    $this->crypt->setSalt($this->generateSalt());
                }

                $encrypted = $this->crypt->encrypt($this->plaintext);
                $this->assertNotEmpty($encrypted);

                $decrypted = $this->crypt->decrypt($encrypted);
                $this->assertNotFalse($decrypted);
                $this->assertEquals($this->plaintext, $decrypted);
            }
        }
    }

    public function testEncryptWithoutKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->encrypt('test');
    }

    public function testEncryptEmptyData()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to encrypt cannot be empty');
        $this->crypt->encrypt('');
    }

    public function testEncryptWithoutSalt()
    {
        $this->crypt->setKey($this->generateKey());
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The salt (IV) cannot be empty');
        $this->crypt->encrypt($this->plaintext);
    }

    public function testDecryptEmptyData()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The data to decrypt cannot be empty');
        $this->crypt->decrypt('');
    }

    public function testDecryptWithoutKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->decrypt($this->plaintext);
    }

    public function testSetOptions()
    {
        $options = [
            'algo'    => $this->default_algo,
            'mode'    => $this->default_mode
        ];
        $this->crypt->setOptions($options);

        $this->assertEquals($options['algo'], $this->crypt->getAlgorithm());
        $this->assertEquals($options['mode'], $this->crypt->getMode());

        $options = [
            'key'     => str_repeat('x', $this->crypt->getKeySize()),
            'iv'      => str_repeat('1', $this->crypt->getSaltSize()),
            'padding' => 'nopadding'
        ];
        $this->crypt->setOptions($options);

        $this->assertEquals($options['key'], $this->crypt->getKey());
        $this->assertEquals($options['iv'], $this->crypt->getSalt());
        $this->assertInstanceOf(NoPadding::class, $this->crypt->getPadding());
    }

    public function testSetPaddingPluginManager()
    {
        $this->crypt->setPaddingPluginManager(
            $this->getMockBuilder(ContainerInterface::class)->getMock()
        );
        $this->assertInstanceOf(ContainerInterface::class, $this->crypt->getPaddingPluginManager());
    }

    public function testSetWrongPaddingPluginManager()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setPaddingPluginManager(\stdClass::class);
    }

    public function testSetNotExistingPaddingPluginManager()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->crypt->setPaddingPluginManager('Foo');
    }

    protected function generateKey()
    {
        return Rand::getBytes($this->crypt->getKeySize());
    }

    protected function generateSalt()
    {
        if ($this->crypt->getSaltSize() > 0) {
            return Rand::getBytes($this->crypt->getSaltSize());
        }
    }
}
