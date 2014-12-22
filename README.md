aes-min
=======

Minimal AES ([Wikipedia][1]) encryption.

This aims to be suitable for small embedded systems with limited RAM and ROM.

It includes optional on-the-fly key schedule calculation, for minimal RAM usage if required in a very RAM-constrained application. For systems with sufficient RAM, there is also encryption and decryption with a pre-calculated key schedule.

Normally the S-box implementation is by a simple 256-byte table look-up. An optional smaller S-box implementation is included for a *very* ROM-constrained application, where a 256-byte look-up table might be too big. This would only be expected to be necessary for especially tiny target applications, e.g. an automotive keyless entry remote.

Testing
-------

This has had minimal testing, by inspection of encryption/decryption of a few of the test vectors.


[1]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard

