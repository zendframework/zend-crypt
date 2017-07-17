# Changelog

All notable changes to this project will be documented in this file, in reverse
chronological order by release.

## 3.2.1 - 2017-17-07

### Added

- [#42](https://github.com/zendframework/zend-crypt/pull/42) Added the CTR mode
  for OpenSSL.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- [#48](https://github.com/zendframework/zend-crypt/pull/48) Incorrect Rsa type
  declaration in Hybrid constructor.


## 3.2.0 - 2016-12-06

### Added

- [#38](https://github.com/zendframework/zend-crypt/pull/38) Support of GCM and
  CCM encryption mode for OpenSSL with PHP 7.1+

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.

## 3.1.0 - 2016-08-11

### Added

- [#32](https://github.com/zendframework/zend-crypt/pull/32) adds a new Hybrid
  encryption utility, to allow OpenPGP-like encryption/decryption of messages
  using OpenSSL. See the documentation for details.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.

## 3.0.0 - 2016-06-21

### Added

- [#22](https://github.com/zendframework/zend-crypt/pull/22) adds a requirement
  on `ext/mbstring` in order to install successfully.
- [#25](https://github.com/zendframework/zend-crypt/pull/25) adds a new
  symmetric encryption adapter for the OpenSSL extension; this is now the
  default adapter used internally by the component when symmetric encryption is
  required.
- [#25](https://github.com/zendframework/zend-crypt/pull/25) adds support for
  zend-math v3.
- [#26](https://github.com/zendframework/zend-crypt/pull/26) adds
  `Zend\Crypt\Password\Bcrypt::benchmarkCost()`, which allows you to find the
  maximum cost value possible for your hardware within a 50ms timeframe.
- [#11](https://github.com/zendframework/zend-crypt/pull/11) adds a new option
  to the `Zend\Crypt\PublicKey\RsaOptions` class, `openssl_padding` (or
  `setOpensslPadding()`; this is now consumed in
  `Zend\Crypt\PublicKey\Rsa::encrypt()` and
  `Zend\Crypt\PublicKey\Rsa::decrypt()`, instead of the optional `$padding`
  argument.

### Deprecated

- [#25](https://github.com/zendframework/zend-crypt/pull/25) deprecates usage of the
  mcrypt symmetric encryption adapter when used on PHP 7 versions, as PHP 7.1
  will deprecate the mcrypt extension.

### Removed

- [#11](https://github.com/zendframework/zend-crypt/pull/11) removes the
  optional `$padding` argument from each of `Zend\Crypt\PublicKey\Rsa`'s
  `encrypt()` and `decrypt()` methods; you can now specify the value via the
  `RsaOptions`.
- [#25](https://github.com/zendframework/zend-crypt/pull/25) removes support for
  zend-math v2 versions.
- [#29](https://github.com/zendframework/zend-crypt/pull/29) removes support for
  PHP 5.5.

### Fixed

- [#22](https://github.com/zendframework/zend-crypt/pull/22) updates all
  occurrences of `substr()` and `strlen()` to use `mb_substr()` and
  `mb_strlen()`, respectively. This provides better security with binary values.
- [#25](https://github.com/zendframework/zend-crypt/pull/25) updates the
  `Zend\Crypt\Password\Bcrypt` implementation to use `password_hash()` and
  `password_verify()` internally, as they are supported in all PHP versions we
  support.
- [#19](https://github.com/zendframework/zend-crypt/pull/19) fixes the
  `DiffieHellman` publickey implementation to initialize the `BigInteger`
  adapter from zend-math as the first operation of its constructor, fixing a
  fatal error that occurs when binary data is provided.

## 2.6.0 - 2016-02-03

### Added

- [#18](https://github.com/zendframework/zend-crypt/pull/18) adds documentation,
  and publishes it to https://zendframework.github.io/zend-crypt/

### Deprecated

- Nothing.

### Removed

- Removes the (development) dependency on zend-config; tests that used it
  previously have been updated to use `ArrayObject`, which implements the same
  behavior being tested.

### Fixed

- [#4](https://github.com/zendframework/zend-crypt/pull/4) replaces
  the zend-servicemanager with container-interop, and refactors the
  various plugin managers to implement that interface instead of extending the
  `AbstractPluginManager`.

## 2.5.2 - 2015-11-23

### Added

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- **ZF2015-10**: `Zend\Crypt\PublicKey\Rsa\PublicKey` has a call to `openssl_public_encrypt()`
  which used PHP's default `$padding` argument, which specifies
  `OPENSSL_PKCS1_PADDING`, indicating usage of PKCS1v1.5 padding. This padding
  has a known vulnerability, the
  [Bleichenbacher's chosen-ciphertext attack](http://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5),
  which can be used to recover an RSA private key. This release contains a patch
  that changes the padding argument to use `OPENSSL_PKCS1_OAEP_PADDING`.

  Users upgrading to this version may have issues decrypting previously stored
  values, due to the change in padding. If this occurs, you can pass the
  constant `OPENSSL_PKCS1_PADDING` to a new `$padding` argument in
  `Zend\Crypt\PublicKey\Rsa::encrypt()` and `decrypt()` (though typically this
  should only apply to the latter):

  ```php
  $decrypted = $rsa->decrypt($data, $key, $mode, OPENSSL_PKCS1_PADDING);
  ```

  where `$rsa` is an instance of `Zend\Crypt\PublicKey\Rsa`.

  (The `$key` and `$mode` argument defaults are `null` and
  `Zend\Crypt\PublicKey\Rsa::MODE_AUTO`, if you were not using them previously.)

  We recommend re-encrypting any such values using the new defaults.

## 2.4.9 - 2015-11-23

### Added

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- **ZF2015-10**: `Zend\Crypt\PublicKey\Rsa\PublicKey` has a call to `openssl_public_encrypt()`
  which used PHP's default `$padding` argument, which specifies
  `OPENSSL_PKCS1_PADDING`, indicating usage of PKCS1v1.5 padding. This padding
  has a known vulnerability, the
  [Bleichenbacher's chosen-ciphertext attack](http://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5),
  which can be used to recover an RSA private key. This release contains a patch
  that changes the padding argument to use `OPENSSL_PKCS1_OAEP_PADDING`.

  Users upgrading to this version may have issues decrypting previously stored
  values, due to the change in padding. If this occurs, you can pass the
  constant `OPENSSL_PKCS1_PADDING` to a new `$padding` argument in
  `Zend\Crypt\PublicKey\Rsa::encrypt()` and `decrypt()` (though typically this
  should only apply to the latter):

  ```php
  $decrypted = $rsa->decrypt($data, $key, $mode, OPENSSL_PKCS1_PADDING);
  ```

  where `$rsa` is an instance of `Zend\Crypt\PublicKey\Rsa`.

  (The `$key` and `$mode` argument defaults are `null` and
  `Zend\Crypt\PublicKey\Rsa::MODE_AUTO`, if you were not using them previously.)

  We recommend re-encrypting any such values using the new defaults.
>>>>>>> hotfix/5
