aes-min
=======

Minimal AES-128 ([Wikipedia][1]) encryption.

This aims to be suitable for small embedded systems with limited RAM and ROM.

It includes optional on-the-fly key schedule calculation, for minimal RAM usage if required in a very RAM-constrained application. For systems with sufficient RAM, there is also encryption and decryption with a pre-calculated key schedule.

Normally the S-box implementation is by a simple 256-byte table look-up. An optional smaller S-box implementation is included for a *very* ROM-constrained application, where a 256-byte look-up table might be too big. This would only be expected to be necessary for especially tiny target applications, e.g. an automotive keyless entry remote.

Encryption modes
----------------

Encryption modes (CBC, OFB, etc) are not implemented. This only provides the core AES encryption operation, and leaves it to the developer to implement the encryption mode. This is because for small embedded systems, there are so many possible ways to handle the data in a memory-constrained system, it's not possible to provide an API that suits the needs of every system.

In most cases, implementation of the encryption mode is reasonably straight-forward, requiring only a few block XOR operations. The function `aes_block_xor()` can be used for the block XOR operation.

AES-GCM encryption mode
-----------------------

[GCM encryption mode (Galois/Counter Mode)][2] is an authenticated encryption mode, which uses a Galois 128-bit multiply operation. Code is provided to do the 128-bit Galois multiply operation needed for GCM mode. Several implementations are provided, depending on the required trade-off between speed and RAM consumption:

* a bit-by-bit implementation (slow but requiring minimal RAM)
* a table implementation using an 8-bit table look-up (fast, but requiring 4,080 bytes of calculated table data per key)
* a 4-bit table look-up implementation (moderately fast, requiring 480 bytes of calculated table data per key)

Testing
-------

Test programs are included, which test the S-box implementation and encrypt and decrypt operations.

Encryption and decryption are tested against some files in the official [test vectors][3]. Specifically, the ECB mode test files were used, for AES-128. These files:

* `ECBGFSbox128.rsp`
* `ECBKeySbox128.rsp`
* `ECBVarKey128.rsp`
* `ECBVarTxt128.rsp`

The test vectors were parsed and converted to C data structures using a Python program.

For AES-GCM mode, the Galois 128-bit multiply is tested against [these AES-GCM test vectors from NIST][4].

When using autotools, run the tests via:

    make check

License
-------

This code is released under the MIT license. See [`LICENSE.txt`][5] for details.


[1]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[2]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[3]: http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
[4]: https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/mac/gcmtestvectors.zip
[5]: LICENSE.txt
