<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\FileCipher;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\Exception;
use Zend\Crypt\FileCipher;
use Zend\Crypt\Hmac;
use Zend\Crypt\Symmetric\Exception as SymmetricException;
use Zend\Math\Rand;

/**
 * @group      Zend_Crypt
 */
abstract class AbstractFileCipherTest extends TestCase
{
    /**
     * @var fileCipher
     */
    protected $fileCipher;

    /**
     * @var string
     */
    protected $fileIn;

    /**
     * @var string
     */
    protected $fileOut;

    public function setUp()
    {
        $this->assertInstanceOf(FileCipher::class, $this->fileCipher);
    }

    public function tearDown()
    {
        if (file_exists($this->fileIn)) {
            unlink($this->fileIn);
        }
        if (file_exists($this->fileOut)) {
            unlink($this->fileOut);
        }
    }

    public function testBufferConstant()
    {
        // The buffer size must be always the same to be able to decrypt
        $this->assertEquals(1048576, FileCipher::BUFFER_SIZE);
    }

    public function testSetKeyIteration()
    {
        $this->fileCipher->setKeyIteration(5000);
        $this->assertEquals(5000, $this->fileCipher->getKeyIteration());
    }

    public function testSetKey()
    {
        $this->fileCipher->setKey('test');
        $this->assertEquals('test', $this->fileCipher->getKey());
    }

    public function testSetEmptyKey()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The key cannot be empty');
        $this->fileCipher->setKey('');
    }

    public function testSetCipherAlgorithm()
    {
        $this->fileCipher->setCipherAlgorithm('blowfish');
        $this->assertEquals('blowfish', $this->fileCipher->getCipherAlgorithm());
    }

    public function testSetCipherAlgorithmFail()
    {
        $this->expectException(SymmetricException\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The algorithm unknown is not supported by %s',
            get_class($this->fileCipher->getCipher())
        ));
        $this->fileCipher->setCipherAlgorithm('unknown');
    }

    public function testGetCipherSupportedAlgorithms()
    {
        $this->assertInternalType('array', $this->fileCipher->getCipherSupportedAlgorithms());
    }

    public function testSetHashAlgorithm()
    {
        $this->fileCipher->setHashAlgorithm('sha1');
        $this->assertEquals('sha1', $this->fileCipher->getHashAlgorithm());
    }

    public function testSetWrongHashAlgorithm()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The specified hash algorithm \'unknown\' is not supported by Zend\Crypt\Hash');
        $this->fileCipher->setHashAlgorithm('unknown');
    }

    public function testSetPbkdf2HashAlgorithm()
    {
        $this->fileCipher->setPbkdf2HashAlgorithm('sha1');
        $this->assertEquals('sha1', $this->fileCipher->getPbkdf2HashAlgorithm());
    }

    public function testSetWrongPbkdf2HashAlgorithm()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The specified hash algorithm \'unknown\' is not supported by Zend\Crypt\Hash');
        $this->fileCipher->setPbkdf2HashAlgorithm('unknown');
    }

    public function testEncryptDecryptFile()
    {
        $this->fileCipher->setKey('test');

        // Test 5 files with a random size between 1 Kb and 5 Mb
        for ($i = 1; $i <= 5; $i++) {
            $fileIn  = $this->generateTmpFile(Rand::getInteger(1024, 1048576 * 5), Rand::getBytes(1));
            $fileOut = $fileIn . '.enc';

            // encrypt without compression
            $this->assertTrue($this->fileCipher->encrypt($fileIn, $fileOut, false));

            $paddingSize = $this->fileCipher->getCipher()->getBlockSize();
            $this->assertEquals(
                filesize($fileOut),
                filesize($fileIn) +
                                $this->fileCipher->getCipher()->getSaltSize() +
                                Hmac::getOutputSize($this->fileCipher->getHashAlgorithm()) +
                $paddingSize - filesize($fileIn) % $paddingSize
            );

            $decryptFile = $fileOut . '.dec';
            // decrypt
            $this->assertTrue($this->fileCipher->decrypt($fileOut, $decryptFile));
            $this->assertEquals(filesize($fileIn), filesize($decryptFile));
            $this->assertEquals(file_get_contents($fileIn), file_get_contents($decryptFile));

            unlink($fileIn);
            unlink($fileOut);
            unlink($decryptFile);
        }
    }

    public function testDecryptFileNoValidAuthenticate()
    {
        $this->fileIn  = $this->generateTmpFile(1048576, Rand::getBytes(1));
        $this->fileOut = $this->fileIn . '.enc';

        $this->fileCipher->setKey('test');
        $this->assertTrue($this->fileCipher->encrypt($this->fileIn, $this->fileOut, false));

        $fileOut2 = $this->fileIn . '.dec';
        $this->assertTrue($this->fileCipher->decrypt($this->fileOut, $fileOut2, false));
        unlink($fileOut2);

        // Tampering of the encrypted file
        $ciphertext = file_get_contents($this->fileOut);
        $ciphertext[0] = chr((ord($ciphertext[0]) + 1) % 256);
        file_put_contents($this->fileOut, $ciphertext);

        $this->assertFalse($this->fileCipher->decrypt($this->fileOut, $fileOut2, false));
        $this->assertFileNotExists($fileOut2);
    }

    public function testEncryptFileWithNoKey()
    {
        $this->fileIn  = $this->generateTmpFile(1048576, Rand::getBytes(1));
        $this->fileOut = $this->fileIn . '.enc';

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('No key specified for encryption');
        $this->fileCipher->encrypt($this->fileIn, $this->fileOut);
    }

    public function testDecryptFileWithNoKey()
    {
        $this->fileIn  = $this->generateTmpFile(1048576, Rand::getBytes(1));
        $this->fileOut = $this->fileIn . '.enc';

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('No key specified for decryption');
        $this->fileCipher->decrypt($this->fileIn, $this->fileOut);
    }

    public function testEncryptFileInvalidInputFile()
    {
        $randomFile = uniqid('Invalid_File', true);
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('I cannot open the %s file', $randomFile));
        $this->fileCipher->setKey('test');
        $this->fileCipher->encrypt($randomFile, '');
    }

    public function testDecryptFileInvalidInputFile()
    {
        $randomFile = uniqid('Invalid_File', true);
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('I cannot open the %s file', $randomFile));
        $this->fileCipher->setKey('test');
        $this->fileCipher->decrypt($randomFile, '');
    }

    public function testEncryptFileInvalidOutputFile()
    {
        $this->fileIn  = $this->generateTmpFile(1024);
        $this->fileOut = $this->generateTmpFile(1024);

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The file %s already exists', $this->fileOut));
        $this->fileCipher->setKey('test');
        $this->fileCipher->encrypt($this->fileIn, $this->fileOut);
    }

    public function testDecryptFileInvalidOutputFile()
    {
        $this->fileIn  = $this->generateTmpFile(1024);
        $this->fileOut = $this->generateTmpFile(1024);

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The file %s already exists', $this->fileOut));
        $this->fileCipher->setKey('test');
        $this->fileCipher->decrypt($this->fileIn, $this->fileOut);
    }

    /**
     * Generate a temporary file with a selected size
     *
     * @param  string $size
     * @param  string $content
     * @return string
     */
    protected function generateTmpFile($size, $content = 'A')
    {
        $fileName = sys_get_temp_dir() . '/' . uniqid('ZF2_FileCipher_test', true);
        $content  = str_repeat('A', $size / strlen($content) + 1);
        file_put_contents($fileName, substr($content, 0, $size));

        return $fileName;
    }
}
