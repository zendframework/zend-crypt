<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Password;

use ArrayObject;
use PHPUnit\Framework\TestCase;
use Zend\Crypt\Password\Bcrypt;
use Zend\Crypt\Password\Exception;

class BcryptSaltTest extends TestCase
{
    /** @var Bcrypt */
    public $bcrypt;

    /** @var string */
    public $salt;

    /** @var string */
    public $bcryptPassword;

    /** @var string */
    public $password;

    public function setUp()
    {
        if (PHP_VERSION_ID >= 70000) {
            $this->markTestSkipped(
                sprintf('I cannot execute %s with PHP 7+', __CLASS__)
            );
        }
        $this->bcrypt   = new Bcrypt();
        $this->salt     = '1234567890123456789012';
        $this->password = 'test';
        $this->prefix   = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$123456789012345678901uIcehzOq0s9RvVtyXJFIsuuxuE2XZRMq';
    }

    public function testConstructByOptions()
    {
        $options = [
            'cost' => '15',
            'salt' => $this->salt
        ];
        $bcrypt  = new Bcrypt($options);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    /**
     * This test uses ArrayObject to simulate a Zend\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig()
    {
        $options = [
            'cost' => '15',
            'salt' => $this->salt
        ];
        $config  = new ArrayObject($options);
        $bcrypt  = new Bcrypt($config);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    public function testSetSalt()
    {
        $this->bcrypt->setSalt($this->salt);
        $this->assertEquals($this->salt, $this->bcrypt->getSalt());
    }

    public function testSetSmallSalt()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The length of the salt must be at least %d bytes',
            Bcrypt::MIN_SALT_SIZE
        ));
        $this->bcrypt->setSalt('small salt');
    }

    public function testCreateWithSalt()
    {
        $this->bcrypt->setSalt($this->salt);
        $password = $this->bcrypt->create($this->password);
        $this->assertEquals($password, $this->bcryptPassword);
    }

    public function testVerify()
    {
        $this->assertTrue($this->bcrypt->verify($this->password, $this->bcryptPassword));
        $this->assertFalse($this->bcrypt->verify(substr($this->password, -1), $this->bcryptPassword));
    }

    public function testPasswordWith8bitCharacter()
    {
        $password = 'test' . chr(128);
        $this->bcrypt->setSalt($this->salt);

        $this->assertEquals(
            '$2y$10$123456789012345678901uzhRRynEzg8i5sfojdxRRwS90XfVE9vW',
            $this->bcrypt->create($password)
        );
    }
}
