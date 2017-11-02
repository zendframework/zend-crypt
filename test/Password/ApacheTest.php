<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Password;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\Password\Apache;
use Zend\Crypt\Password\Bcrypt;
use Zend\Crypt\Password\Exception;

/**
 * @group      Zend_Crypt
 */
class ApacheTest extends TestCase
{
    /** @var Apache */
    public $apache;

    public function setUp()
    {
        $this->apache = new Apache();
    }

    public function testConstruct()
    {
        $apache = new Apache(['format' => 'crypt']);
        $this->assertInstanceOf(Apache::class, $apache);
    }

    public function testWrongConstruct()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        new Apache('crypt');
    }

    public function testWrongParamConstruct()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        new Apache(['format' => 'crypto']);
    }

    public function testSetUserName()
    {
        $result = $this->apache->setUserName('test');
        $this->assertInstanceOf(Apache::class, $result);
        $this->assertEquals('test', $this->apache->getUserName());
    }

    public function testSetFormat()
    {
        $result = $this->apache->setFormat('crypt');
        $this->assertInstanceOf(Apache::class, $result);
        $this->assertEquals('crypt', $this->apache->getFormat());
    }

    public function testSetWrongFormat()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->apache->setFormat('test');
    }

    public function testSetAuthName()
    {
        $result = $this->apache->setAuthName('test');
        $this->assertInstanceOf(Apache::class, $result);
        $this->assertEquals('test', $this->apache->getAuthName());
    }

    public function testCrypt()
    {
        $this->apache->setFormat('crypt');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals(13, strlen($hash));
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testSha1()
    {
        $this->apache->setFormat('sha1');
        $hash = $this->apache->create('myPassword');
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testMd5()
    {
        $this->apache->setFormat('md5');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals('$apr1$', substr($hash, 0, 6));
        $this->assertEquals(37, strlen($hash));
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testDigest()
    {
        $this->apache->setFormat('digest');
        $this->apache->setUserName('Enrico');
        $this->apache->setAuthName('Auth');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals(32, strlen($hash));
    }

    public function testDigestWithoutPreset()
    {
        $this->apache->setFormat('digest');

        $this->expectException(Exception\RuntimeException::class);
        $this->apache->create('myPassword');
    }

    public function testDigestWithoutAuthName()
    {
        $this->apache->setFormat('digest');
        $this->apache->setUserName('Enrico');

        $this->expectException(Exception\RuntimeException::class);
        $this->apache->create('myPassword');
    }

    public function testDigestWithoutUserName()
    {
        $this->apache->setFormat('digest');
        $this->apache->setAuthName('Auth');

        $this->expectException(Exception\RuntimeException::class);
        $this->apache->create('myPassword');
    }

    /**
     * Test vectors generated using openssl and htpasswd
     *
     * @see http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
     */
    public static function provideTestVectors()
    {
        return [
            // openssl passwd -apr1 -salt z0Hhe5Lq myPassword
            ['myPassword', '$apr1$z0Hhe5Lq$6YdJKbkrJg77Dvw2gpuSA1'],
            // openssl passwd -crypt -salt z0Hhe5Lq myPassword
            ['myPassword', 'z0yXKQm465G4o'],
            // htpasswd -nbs myName myPassword
            ['myPassword', '{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE='],
        ];
    }

    /**
     * @dataProvider provideTestVectors
     */
    public function testVerify($password, $hash)
    {
        $this->assertTrue($this->apache->verify($password, $hash));
    }

    public function testApr1Md5WrongSaltFormat1()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->apache->verify('myPassword', '$apr1$z0Hhe5Lq3$6YdJKbkrJg77Dvw2gpuSA1');
    }

    public function testApr1Md5WrongSaltFormat2()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->apache->verify('myPassword', '$apr1$z0Hhe5L&$6YdJKbkrJg77Dvw2gpuSA1');
    }

    public function testCanVerifyBcryptHashes()
    {
        $bcrypt = new Bcrypt();
        $hash = $bcrypt->create('myPassword');
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }
}
