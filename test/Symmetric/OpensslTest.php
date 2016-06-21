<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2016 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use Zend\Crypt\Symmetric\Openssl;

/**
 * @group      Zend_Crypt
 */
class OpensslTest extends AbstractTest
{
    protected $adapterClass = Openssl::class;

    protected $default_algo = 'aes';

    protected $default_mode = 'cbc';

    protected $default_padding = 'pkcs7';
}
