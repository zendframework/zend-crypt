<?php
/**
 * @link      http://github.com/zendframework/zend-crypt for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use PHPUnit\Framework\TestCase;
use Zend\Crypt\Symmetric\Mcrypt;

class McryptDeprecatedTest extends TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID < 70100) {
            $this->markTestSkipped('The Mcrypt deprecated test is for PHP 7.1+');
        }
    }

    public function testDeprecated()
    {
        $this->expectException(\PHPUnit\Framework\Error\Deprecated::class);
        new Mcrypt();
    }
}
