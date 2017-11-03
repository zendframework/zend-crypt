<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt;

use Interop\Container\ContainerInterface;
use PHPUnit\Framework\TestCase;
use Zend\Crypt\Exception as CryptException;
use Zend\Crypt\Symmetric\Exception;
use Zend\Crypt\Symmetric\SymmetricInterface;
use Zend\Crypt\SymmetricPluginManager;

class SymmetricPluginManagerTest extends TestCase
{
    public function getSymmetrics()
    {
        if (PHP_VERSION_ID >= 70100) {
            return [
                ['openssl'],
            ];
        }

        return [
            ['mcrypt'],
            ['openssl'],
        ];
    }

    public function testConstruct()
    {
        $plugin = new SymmetricPluginManager();
        $this->assertInstanceOf(ContainerInterface::class, $plugin);
    }

    /**
     * @dataProvider getSymmetrics
     */
    public function testHas($symmetric)
    {
        $plugin = new SymmetricPluginManager();
        $this->assertTrue($plugin->has($symmetric));
    }

    /**
     * @dataProvider getSymmetrics
     */
    public function testGet($symmetric)
    {
        if (! extension_loaded($symmetric)) {
            $this->expectException(Exception\RuntimeException::class);
        }
        $plugin = new SymmetricPluginManager();
        $this->assertInstanceOf(SymmetricInterface::class, $plugin->get($symmetric));
    }

    public function testGetError()
    {
        $plugin = new SymmetricPluginManager();

        $this->expectException(CryptException\NotFoundException::class);
        $plugin->get('foo');
    }
}
