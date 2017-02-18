AESf
==========

AESf package combines AES encryption, sha1HMAC verification and RFC2898 key derivation, which provide a very security way to encryp/decrypt data in golang.

**Key features**

- Support AES-128, AES-192, or AES-256.
- Use CTR mode for encrytion.
- Sha1HMAC for signature authentication.
- Password verify before decryption.
- RFC2898 as salt generater.

The whole idea is coming from @BrianGladman 's blog [http://www.gladman.me.uk/cryptography_technology/fileencrypt](http://www.gladman.me.uk/cryptography_technology/fileencrypt).

Installation
------------

This package can be installed with the go get command:

    go get github.com/xeodou/aesf

Documentation
-------------

API documentation can be found here: http://godoc.org/github.com/xeodou/aesf

Examples can be found under the `./example_test.go` directory


License
-------

MIT

Author
------

[xeodou](https://xeodou.me)
