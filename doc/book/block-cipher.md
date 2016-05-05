# Encrypt/decrypt using block ciphers

`Zend\Crypt\BlockCipher` implements encrypt-then-authenticate mode using
[HMAC](http://en.wikipedia.org/wiki/HMAC) to provide authentication.

The symmetric cipher can be chosen with a specific adapter that implements
`Zend\Crypt\Symmetric\SymmetricInterface`. We support the symmmetric encryption
algorithms offered by [OpenSSL](http://php.net/manual/en/book.openssl.php) and
[Mcrypt](http://php.net/manual/en/book.mcrypt.php) extensions.

In the following code, we detail an example of using the `BlockCipher` class to
encrypt-then-authenticate a string using the
[AES-256](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) block cipher
and the HMAC algorithm (using the [SHA-256](http://en.wikipedia.org/wiki/SHA-2)
hash function).


> ## Mcrypt
>
> The Mcrypt extension is based on the libmcrypt library. Unfortunately, at the
> time of writing, the project is dead, having been unmaintained for around 8
> years, with the last release (version 2.5.8) having occurred in February 2007.
> 
> Starting with PHP 7.1, the Mcrypt extension will be
> [considered deprecated](https://wiki.php.net/rfc/mcrypt-viking-funeral).
> For these reasons, **we strongly suggest using only the Openssl adapter**.
> 
> Starting with zend-crypt 3.0, the Openssl adapter is the default (for example,
> by `Zend\Crypt\FileCipher`), and all examples now only demonstrate that
> adapter.

```php
use Zend\Crypt\BlockCipher;

$blockCipher = BlockCipher::factory('openssl', array('algo' => 'aes'));
$blockCipher->setKey('encryption key');
$result = $blockCipher->encrypt('this is a secret message');
echo "Encrypted text: $result\n";
```

The `BlockCipher` instance is initialized using a factory method with the name
of the cipher adapter to use (e.g., `openssl`) and the parameters to pass to the adapter
(the AES algorithm). In order to encrypt a string, we need to specify an
encryption key, which we do via the `setKey()` method. Encryption is performed
with the `encrypt()` method.

The output of encryption is a string, encoded in Base64 (default), containing
the HMAC value, the IV vector, and the encrypted text. The encryption mode used
is [CBC](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29)
(with a random [IV](http://en.wikipedia.org/wiki/Initialization_vector) by
default), with the default HMAC hash algorithm of SHA256.  The Openssl adapter
encrypts using the [PKCS\#7 padding](http://en.wikipedia.org/wiki/Padding_%28cryptography%29)
mechanism by default. You can specify a different padding method using a special
adapter (`Zend\Crypt\Symmetric\Padding`). The encryption and authentication keys
used by `BlockCipher` are generated with the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2)
algorithm, used as the key derivation function from the user's key specified
using the `setKey()` method.

> ## Key size
>
> BlockCipher always attempts to use the longest key size for the specified
> cipher. For instance, for the AES algorithm it uses 256 bits, and for the
> [Blowfish](http://en.wikipedia.org/wiki/Blowfish_%28cipher%29) algorithm it
> uses 448 bits.

You can change all the default settings by passing the values to the factory
parameters. For instance, if you want to use the Blowfish algorithm, with the
CFB mode and the HMAC SHA512 hash function, initialize the class as follows:

```php
use Zend\Crypt\BlockCipher;

$blockCipher = BlockCipher::factory(
    'openssl',
    [
        'algo' => 'blowfish',
        'mode' => 'cfb',
        'hash' => 'sha512'
    ]
);
```

> ## Recommendation
>
> If you are not familiar with symmetric encryption techniques, we strongly
> suggest using the default values of the `BlockCipher` class. The default
> values are: AES algorithm, CBC mode, HMAC with SHA256, PKCS\#7 padding.

To decrypt a string we can use the `decrypt()` method. In order to successfully
decrypt a string, we must configure the `BlockCipher` with the same parameters
used during encryption.

We can also initialize the `BlockCipher` manually without using the factory method;
we can inject the symmetric cipher adapter directly via the constructor.
For instance, we can rewrite the previous example as follows:

```php
use Zend\Crypt\BlockCipher;
use Zend\Crypt\Symmetric\Mcrypt;

$blockCipher = new BlockCipher(new Mcrypt(['algo' => 'aes']));
$blockCipher->setKey('encryption key');
$result = $blockCipher->encrypt('this is a secret message');
echo "Encrypted text: $result \n";
```
