# Introduction

zend-crypt provides support for several cryptographic tools, with the following
features:

- encrypt-then-authenticate using symmetric ciphers (the authentication step is
  provided using HMAC);
- encrypt/decrypt using symmetric and public key algorithm (e.g. RSA algorithm);
- generate digital signature using public key algorithm (e.g. RSA algorithm);
- key exchange using the Diffie-Hellman method;
- key derivation function (e.g. using PBKDF2 algorithm);
- secure password hash (e.g. using bcrypt algorithm);
- generate hash values; and
- generate HMAC values.

The main scope of this component is to offer an easy and secure way to protect
and authenticate sensitive data in PHP. Because the use of cryptography is often
complex, we recommend using the component only if you have background on this
topic. For an introduction to cryptography, we suggest the following references:

- Dan Boneh, ["Cryptography course"](https://www.coursera.org/course/crypto),
  Stanford University, Coursera; free online course
- N.Ferguson, B.Schneier, and T.Kohno, ["Cryptography Engineering"](http://www.schneier.com/book-ce.html),
  John Wiley & Sons (2010)
- B.Schneier ["Applied Cryptography"](http://www.schneier.com/book-applied.html),
  John Wiley & Sons (1996)
