<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace ZendTest\Crypt\Symmetric;

use Zend\Crypt\Symmetric\Mcrypt;
use Zend\Crypt\Symmetric\Exception;

/**
 * @group      Zend_Crypt
 */
class McryptTest extends AbstractTest
{
    protected $adapterClass = Mcrypt::class;

    protected $default_algo = 'blowfish';

    protected $default_mode = 'cfb';

    protected $default_padding = 'pkcs7';

    public function testSetShortKey()
    {
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            $this->crypt->setAlgorithm($algo);
            try {
                $result = $this->crypt->setKey('four');
            } catch (\Exception $ex) {
                $result = $ex;
            }
            if ($algo != 'blowfish') {
                $this->assertInstanceOf(
                    Exception\InvalidArgumentException::class,
                    $result
                );
            } else {
                $this->assertInstanceof($this->adapterClass, $result);
            }
        }
    }

}
