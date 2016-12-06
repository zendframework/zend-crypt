<?php
/**
 * @link      http://github.com/zendframework/zend-crypt for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use Zend\Crypt\Symmetric\Mcrypt;

class MCryptDeprecatedTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID < 70100) {
            $this->markTestSkipped('The Mcrypt deprecated test is for PHP 7.1+');
        }
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Deprecated
     */
    public function testDeprecated()
    {
        $mcrypt = new Mcrypt();
    }
}
