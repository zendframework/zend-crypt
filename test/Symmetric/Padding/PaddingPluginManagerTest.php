<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric\Padding;

use Interop\Container\ContainerInterface;
use Zend\Crypt\Symmetric\PaddingPluginManager;
use Zend\Crypt\Symmetric\Padding\PaddingInterface;

class PaddingPluginManagerTest extends \PHPUnit_Framework_TestCase
{
    public function getPaddings()
    {
        return [
            [ 'pkcs7' ],
            [ 'nopadding' ],
            [ 'null' ],
        ];
    }

    public function testConstruct()
    {
        $plugin = new PaddingPluginManager();
        $this->assertInstanceof(ContainerInterface::class, $plugin);
    }

    /**
     * @dataProvider getPaddings
     */
    public function testHas($padding)
    {
        $plugin = new PaddingPluginManager();
        $this->assertTrue($plugin->has($padding));
    }

    /**
     * @dataProvider getPaddings
     */
    public function testGet($padding)
    {
        $plugin = new PaddingPluginManager();
        $this->assertInstanceof(PaddingInterface::class, $plugin->get($padding));
    }

    /**
     * @expectedException Zend\Crypt\Symmetric\Exception\NotFoundException
     */
    public function testGetError()
    {
        $plugin = new PaddingPluginManager();
        $plugin->get('foo');
    }
}
