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
use Zend\Crypt\SymmetricPluginManager;
use Zend\Crypt\Symmetric\SymmetricInterface;
use Zend\Crypt\Symmetric\Exception;

class SymmetricPluginManagerTest extends \PHPUnit_Framework_TestCase
{
    public function getSymmetrics()
    {
        return [
            [ 'mcrypt' ],
            [ 'openssl' ],
        ];
    }

    public function testConstruct()
    {
        $plugin = new SymmetricPluginManager();
        $this->assertInstanceof(ContainerInterface::class, $plugin);
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
        $plugin = new SymmetricPluginManager();
        if (! extension_loaded($symmetric)) {
            $this->setExpectedException(Exception\RuntimeException::class);
        }
        $this->assertInstanceof(SymmetricInterface::class, $plugin->get($symmetric));
    }

    /**
     * @expectedException Zend\Crypt\Exception\NotFoundException
     */
    public function testGetError()
    {
        $plugin = new SymmetricPluginManager();
        $plugin->get('foo');
    }
}
