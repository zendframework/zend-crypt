<?php
namespace Zend\Crypt;

use Zend\Math\Rand;
use Zend\Crypt\PublicKey\Rsa\PublicKey as PubKey;
use Zend\Crypt\PublicKey\Rsa\PrivateKey;

/**
 * Hybrid encryption (OpenPGP like)
 *
 * The data are encrypted using a BlockCipher with a random session key
 * that is encrypted using RSA with the public key of the receiver.
 * The decryption process retrieves the session key using RSA with the private
 * key of the receiver and decrypt the data using the BlockCipher.
 */
class Hybrid
{
    /**
     * @var BlockCipher
     */
    protected $bCipher;

    /**
     * @var Rsa
     */
    protected $rsa;

    /**
     * Constructor
     *
     * @param BlockCipher $blockCipher
     * @param Rsa $public
     */
    public function __construct(BlockCipher $bCipher = null, Rsa $rsa = null)
    {
        $this->bCipher = (null === $bCipher ) ? BlockCipher::factory('openssl') : $bCipher;
        $this->rsa     = (null === $rsa ) ? new PublicKey\Rsa() : $rsa;
    }

    /**
     * Encrypt using a keyrings
     *
     * @param string $plaintext
     * @param array|string $keys
     * @return string
     * @throws RuntimeException
     */
    public function encrypt($plaintext, $keys = null)
    {
        // generate a random session key
        $sessionKey = Rand::getBytes($this->bCipher->getCipher()->getKeySize());

        // encrypt the plaintext with blockcipher algorithm
        $this->bCipher->setKey($sessionKey);
        $ciphertext = $this->bCipher->encrypt($plaintext);

        if (!is_array($keys)) {
            $keys = [ '' => $keys ];
        }

        $encKeys = '';
        // encrypt the session key with public keys
        foreach ($keys as $id => $pubkey) {
            if (is_string($pubkey)) {
                $pubkey = new PubKey($pubkey);
            } elseif (!($pubkey instanceof PubKey)) {
                throw new Exception\RuntimeException(sprintf(
                    "The public key must be a string in PEM format or an instance of %s",
                    PubKey::class
                ));
            }
            $encKeys .= sprintf(
                "%s:%s:",
                base64_encode($id),
                base64_encode($this->rsa->encrypt($sessionKey, $pubkey))
            );
        }
        return $encKeys . ';' . $ciphertext;
    }

    /**
     * Decrypt usign a private key
     *
     * @param string $msg
     * @param string $privateKey
     * @param string $id
     * @return string
     * @throws RuntimeException
     */
    public function decrypt($msg, $privateKey = null, $id = null)
    {
        // get the session key
        list($encKeys, $ciphertext) = explode(';', $msg, 2);

        $keys = explode(':', $encKeys);
        $pos  = array_search(base64_encode($id), $keys);
        if (false === $pos) {
            throw new Exception\RuntimeException(
                "This private key cannot be used for decryption"
            );
        }

        $privKey = new PrivateKey($privateKey);
        // decrypt the session key with privateKey
        $sessionKey = $this->rsa->decrypt(base64_decode($keys[$pos + 1]), $privKey);

        // decrypt the plaintext with the blockcipher algorithm
        $this->bCipher->setKey($sessionKey);
        return $this->bCipher->decrypt($ciphertext, $sessionKey);
    }

    /**
     * Get the BlockCipher adapter
     *
     * @return BlockCipher
     */
    public function getBlockCipherInstance()
    {
        return $this->bCipher;
    }

    /**
     * Get the Rsa instance
     *
     * @return Rsa
     */
    public function getRsaInstance()
    {
        return $this->rsa;
    }
}
