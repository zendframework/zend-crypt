# Encrypt/decrypt a file

`Zend\Crypt\FileCipher` implements the encryption of decryption of a file using a symmetric cipher
in
[CBC](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29)
mode with the encrypt-then-authenticate approach, using [HMAC](http://en.wikipedia.org/wiki/HMAC) to
provide authentication (the same solution used by `Zend\Crypt\BlockCipher` component).

Encrypt and decrypt a file is not an easy task, especially a big file. For instance, in CBC mode you
must be sure to handle the [IV](http://en.wikipedia.org/wiki/Initialization_vector) correctly for
each block. That means, if you are reading a big file you need to use a buffer and be sure to use
the last block of the buffer as new IV for the next encryption step.

The `FileCipher` uses a symmetric cipher, with the `Zend\Crypt\Symmetric\Mcrypt` component.

The usage of this component is very simple, you just need to create an instance of `FileCipher` and
specify the key, and you are ready to encrypt/decrypt any file:

``` sourceCode
use Zend\Crypt\FileCipher;

$fileCipher = new FileCipher;
$fileCipher->setKey('encryption key');
// encryption
if ($fileCipher->encrypt('path/to/file_to_encrypt', 'path/to/output')) {
    echo "The file has been encrypted successfully\n";
}
// decryption
if ($fileCipher->decrypt('path/to/file_to_decrypt', 'path/to/output')) {
    echo "The file has been decrypted successfully\n";
}
```

By default `FileCipher` uses the [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
encryption algorithm (with a key of 256 bit) and the [SHA-256](http://en.wikipedia.org/wiki/SHA-2)
hash algorithm to authenticate the data using the HMAC function. This component uses the
[PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) key derivation algorithm to generate the encryption
key and the authentication key, for the HMAC, based on the key specified using the method
`setKey()`.

If you want to change the encryption algorithm, you can use the `setCipherAlgorithm()` function, for
instance you can specity to use the [Blowfish](http://en.wikipedia.org/wiki/Blowfish_%28cipher%29)
encryption algorihtm using `setCipherAlgorithm('blowfish')`. You can retrieve the list of all the
supported encryption algorithm in your environment using the function
`getCipherSupportedAlgorithms()`, it will return an array of all the algorithm name.

If you need to customize the cipher algorithm, for instance changing the Padding mode, you can
inject your Mcrypt object in the `FileCipher` using the `setCipher()` method. The only parameter of
the cipher that you cannot change is the cipher mode, that will be CBC in any case.

> ## Note
#### Output format
The output of the encryption file is in binary format. We used this format to do not impact on the
output size. If you encrypt a file using the FileCipher component, you will notice that the output
file size is almost the same of the input size, just some bytes more to store the HMAC and the IV
vector. The format of the output is the concatenation of the HMAC, the IV and the encrypted file.
