<?php
/**
 * @see       https://github.com/zendframework/zend-crypt for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   https://github.com/zendframework/zend-crypt/blob/master/LICENSE.md New BSD License
 */

if (class_exists(\PHPUnit_Framework_Error::class)) {
    class_alias(\PHPUnit_Framework_Error::class, \PHPUnit\Framework\Error\Error::class);
}

if (class_exists(\PHPUnit_Framework_Error_Deprecated::class)) {
    class_alias(\PHPUnit_Framework_Error_Deprecated::class, \PHPUnit\Framework\Error\Deprecated::class);
}
