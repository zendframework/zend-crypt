<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace Zend\Crypt\Symmetric;

use Interop\Container\ContainerInterface;
use Traversable;
use Zend\Stdlib\ArrayUtils;

/**
 * Symmetric encryption using the OpenSSL extension
 *
 * NOTE: DO NOT USE only this class to encrypt data.
 * This class doesn't provide authentication and integrity check over the data.
 * PLEASE USE Zend\Crypt\BlockCipher instead!
 */
class Openssl implements SymmetricInterface
{
    const DEFAULT_PADDING = 'pkcs7';

    /**
     * Key
     *
     * @var string
     */
    protected $key;

    /**
     * IV
     *
     * @var string
     */
    protected $iv;

    /**
     * Encryption algorithm
     *
     * @var string
     */
    protected $algo = 'aes';

    /**
     * Encryption mode
     *
     * @var string
     */
    protected $mode = 'cbc';

    /**
     * Padding
     *
     * @var Padding\PaddingInterface
     */
    protected $padding;

    /**
     * Padding plugins
     *
     * @var Interop\Container\ContainerInterface
     */
    protected static $paddingPlugins = null;

    /**
     * Supported cipher algorithms
     *
     * @var array
     */
    protected $supportedAlgos = [
        'aes'      => 'AES-256',
        'blowfish' => 'BF',
        'des'      => 'DES',
        'camellia' => 'CAMELLIA-256',
        'cast5'    => 'CAST5',
        'seed'     => 'SEED'
    ];

    /**
     * Supported encryption modes
     *
     * @var array
     */
    protected $supportedModes = [
        'cbc',
        'cfb',
        'ofb',
        'ecb'
    ];

    /**
     * Block sizes (in bytes) for each supported algorithm
     *
     * @var array
     */
    protected $blockSizes = [
        'aes'      => 16,
        'blowfish' => 8,
        'des'      => 8,
        'camellia' => 16,
        'cast5'    => 8,
        'seed'     => 16
    ];

    /**
     * Key sizes (in bytes) for each supported algorithm
     *
     * @var array
     */
    protected $keySizes = [
        'aes'      => 32,
        'blowfish' => 56,
        'des'      => 8,
        'camellia' => 32,
        'cast5'    => 16,
        'seed'     => 16
    ];

    /**
     * Constructor
     *
     * @param  array|Traversable                  $options
     * @throws Exception\RuntimeException
     * @throws Exception\InvalidArgumentException
     */
    public function __construct($options = [])
    {
        if (!extension_loaded('openssl')) {
            throw new Exception\RuntimeException(
                'You cannot use ' . __CLASS__ . ' without the OpenSSL extension'
            );
        }
        $this->setOptions($options);
        $this->setDefaultOptions($options);
    }

    /**
     * Set default options
     *
     * @param  array $options
     * @return void
     */
    public function setOptions($options)
    {
        if (!empty($options)) {
            if ($options instanceof Traversable) {
                $options = ArrayUtils::iteratorToArray($options);
            } elseif (!is_array($options)) {
                throw new Exception\InvalidArgumentException(
                    'The options parameter must be an array, a Zend\Config\Config object or a Traversable'
                );
            }
            foreach ($options as $key => $value) {
                switch (strtolower($key)) {
                    case 'algo':
                    case 'algorithm':
                        $this->setAlgorithm($value);
                        break;
                    case 'mode':
                        $this->setMode($value);
                        break;
                    case 'key':
                        $this->setKey($value);
                        break;
                    case 'iv':
                    case 'salt':
                        $this->setSalt($value);
                        break;
                    case 'padding':
                        $plugins       = static::getPaddingPluginManager();
                        $padding       = $plugins->get($value);
                        $this->padding = $padding;
                        break;
                }
            }
        }
    }

    /**
     * Set default options
     *
     * @param  array $options
     * @return void
     */
    protected function setDefaultOptions($options = [])
    {
        if (!isset($options['padding'])) {
            $plugins       = static::getPaddingPluginManager();
            $padding       = $plugins->get(self::DEFAULT_PADDING);
            $this->padding = $padding;
        }
    }

    /**
     * Returns the padding plugin manager.  If it doesn't exist it's created.
     *
     * @return ContainerInterface
     */
    public static function getPaddingPluginManager()
    {
        if (static::$paddingPlugins === null) {
            self::setPaddingPluginManager(new PaddingPluginManager());
        }

        return static::$paddingPlugins;
    }

    /**
     * Set the padding plugin manager
     *
     * @param  string|ContainerInterface $plugins
     * @throws Exception\InvalidArgumentException
     * @return void
     */
    public static function setPaddingPluginManager($plugins)
    {
        if (is_string($plugins)) {
            if (! class_exists($plugins) || ! is_subclass_of($plugins, ContainerInterface::class)) {
                throw new Exception\InvalidArgumentException(sprintf(
                    'Unable to locate padding plugin manager via class "%s"; class does not exist or does not implement ContainerInterface',
                    $plugins
                ));
            }
            $plugins = new $plugins();
        }
        if (!$plugins instanceof ContainerInterface) {
            throw new Exception\InvalidArgumentException(sprintf(
                'Padding plugins must implements Interop\Container\ContainerInterface; received "%s"',
                (is_object($plugins) ? get_class($plugins) : gettype($plugins))
            ));
        }
        static::$paddingPlugins = $plugins;
    }

    /**
     * Get the key size for the selected cipher
     *
     * @return int
     */
    public function getKeySize()
    {
        return $this->keySizes[$this->algo];
    }

    /**
     * Set the encryption key
     * If the key is longer than maximum supported, it will be truncated by getKey().
     *
     * @param  string $key
     * @throws Exception\InvalidArgumentException
     * @return self
     */
    public function setKey($key)
    {
        $keyLen = mb_strlen($key, '8bit');
        if (!$keyLen) {
            throw new Exception\InvalidArgumentException('The key cannot be empty');
        }
        if ($keyLen < $this->getKeySize()) {
            throw new Exception\InvalidArgumentException(
                "The size of the key must be at least of " . $this->getKeySize() . " bytes"
            );
        }
        $this->key = $key;
        return $this;
    }

    /**
     * Get the encryption key
     *
     * @return string
     */
    public function getKey()
    {
        if (empty($this->key)) {
            return;
        }
        return mb_substr($this->key, 0, $this->getKeySize(), '8bit');
    }

    /**
     * Set the encryption algorithm (cipher)
     *
     * @param  string $algo
     * @throws Exception\InvalidArgumentException
     * @return self
     */
    public function setAlgorithm($algo)
    {
        if (!array_key_exists($algo, $this->supportedAlgos)) {
            throw new Exception\InvalidArgumentException(
                "The algorithm $algo is not supported by " . __CLASS__
            );
        }
        $this->algo = $algo;
        return $this;
    }

    /**
     * Get the encryption algorithm
     *
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algo;
    }

    /**
     * Set the padding object
     *
     * @param  Padding\PaddingInterface $padding
     * @return self
     */
    public function setPadding(Padding\PaddingInterface $padding)
    {
        $this->padding = $padding;
        return $this;
    }

    /**
     * Get the padding object
     *
     * @return Padding\PaddingInterface
     */
    public function getPadding()
    {
        return $this->padding;
    }

    /**
     * Encrypt
     *
     * @param  string $data
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public function encrypt($data)
    {
        // Cannot encrypt empty string
        if (!is_string($data) || $data === '') {
            throw new Exception\InvalidArgumentException('The data to encrypt cannot be empty');
        }
        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No key specified for the encryption');
        }
        if (null === $this->getSalt()) {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }
        if (null === $this->getPadding()) {
            throw new Exception\InvalidArgumentException('You have to specify a padding method');
        }
        // padding
        $data = $this->padding->pad($data, $this->getBlockSize());
        $iv   = $this->getSalt();
        // encryption
        $result = openssl_encrypt(
            $data,
            strtoupper($this->supportedAlgos[$this->algo] . '-' . $this->mode),
            $this->getKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        if (false === $result) {
            $errMsg = '';
            while ($msg = openssl_error_string()) {
                $errMsg .= $msg;
            }
            throw new Exception\RuntimeException(
                sprintf("OpenSSL error: %s", $errMsg)
            );
        }
        return $iv . $result;
    }

    /**
     * Decrypt
     *
     * @param  string $data
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public function decrypt($data)
    {
        if (empty($data)) {
            throw new Exception\InvalidArgumentException('The data to decrypt cannot be empty');
        }
        if (null === $this->getKey()) {
            throw new Exception\InvalidArgumentException('No key specified for the decryption');
        }
        if (null === $this->getPadding()) {
            throw new Exception\InvalidArgumentException('You have to specify a padding method');
        }
        $iv         = mb_substr($data, 0, $this->getSaltSize(), '8bit');
        $ciphertext = mb_substr($data, $this->getSaltSize(), null, '8bit');
        $result     = openssl_decrypt(
            $ciphertext,
            strtoupper($this->supportedAlgos[$this->algo] . '-' . $this->mode),
            $this->getKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        if (false === $result) {
            $errMsg = '';
            while ($msg = openssl_error_string()) {
                $errMsg .= $msg;
            }
            throw new Exception\RuntimeException(
                sprintf("OpenSSL error: %s", $errMsg)
            );
        }
        // unpadding
        return $this->padding->strip($result);
    }

    /**
     * Get the salt (IV) size
     *
     * @return int
     */
    public function getSaltSize()
    {
        return openssl_cipher_iv_length($this->supportedAlgos[$this->algo] . '-' . strtoupper($this->mode));
    }

    /**
     * Get the supported algorithms
     *
     * @return array
     */
    public function getSupportedAlgorithms()
    {
        $opensslAlgos = openssl_get_cipher_methods(true);
        $algos        = [];
        foreach ($this->supportedAlgos as $name => $algo) {
            if (in_array($algo . '-CBC', $opensslAlgos)) {
                $algos []= $name;
            }
        }
        return $algos;
    }

    /**
     * Set the salt (IV)
     *
     * @param  string $salt
     * @throws Exception\InvalidArgumentException
     * @return self
     */
    public function setSalt($salt)
    {
        if (empty($salt)) {
            throw new Exception\InvalidArgumentException('The salt (IV) cannot be empty');
        }
        if (mb_strlen($salt, '8bit') < $this->getSaltSize()) {
            throw new Exception\InvalidArgumentException(
                'The size of the salt (IV) must be at least ' . $this->getSaltSize() . ' bytes'
            );
        }
        $this->iv = $salt;
        return $this;
    }

    /**
     * Get the salt (IV) according to the size requested by the algorithm
     *
     * @return string
     */
    public function getSalt()
    {
        if (empty($this->iv)) {
            return;
        }
        if (mb_strlen($this->iv, '8bit') < $this->getSaltSize()) {
            throw new Exception\RuntimeException(
                'The size of the salt (IV) must be at least ' . $this->getSaltSize() . ' bytes'
            );
        }
        return mb_substr($this->iv, 0, $this->getSaltSize(), '8bit');
    }

    /**
     * Get the original salt value
     *
     * @return string
     */
    public function getOriginalSalt()
    {
        return $this->iv;
    }

    /**
     * Set the cipher mode
     *
     * @param  string $mode
     * @throws Exception\InvalidArgumentException
     * @return self
     */
    public function setMode($mode)
    {
        if (! empty($mode)) {
            if (! in_array($this->supportedAlgos[$this->algo] . '-' . strtoupper($mode), openssl_get_cipher_methods(true))) {
                throw new Exception\InvalidArgumentException(
                    "The mode $mode is not supported by " . __CLASS__
                );
            }
            $this->mode = $mode;
        }
        return $this;
    }

    /**
     * Get the cipher mode
     *
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * Get all supported encryption modes
     *
     * @return array
     */
    public function getSupportedModes()
    {
        $algorithms = openssl_get_cipher_methods(true);
        $modes      = [];
        foreach ($this->supportedModes as $mode) {
            if (in_array($this->supportedAlgos[$this->algo] . '-' . $mode, $algorithms)) {
                $modes []= $mode;
            }
        }
        return $modes;
    }

    /**
     * Get the block size
     *
     * @return int
     */
    public function getBlockSize()
    {
        return $this->blockSizes[$this->algo];
    }
}
