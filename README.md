# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic operations (e.g.,
hashing, encryption, message authentication codes, and authenticated encryption) in complex protocols. Inspired by
TupleHash, STROBE, Noise Protocol's stateful objects, Merlin transcripts, and Xoodyak's Cyclist mode, Lockstitch
uses [SHA-384], [AES-256], and [GMAC] to provide 10+ Gb/sec performance on modern processors at a 128-bit security
level.

[SHA-384]: https://doi.org/10.6028/NIST.FIPS.180-4

[AES-256]: https://doi.org/10.6028/NIST.FIPS.197-upd1

[GMAC]: https://doi.org/10.6028/NIST.SP.800-38D

## CAUTION

⚠️ You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. The design is documented
in [`design.md`](design.md); read it and see if the arguments therein are convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Design

A Lockstitch protocol is a stateful object which has five different operations:

* `Init`: Initializes a protocol with a domain separation string.
* `Mix`: Mixes a piece of data into the protocol's state, making all future outputs dependent on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's state.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's state as the key.
* `Seal`/`Open`: Encrypts and decrypts data with authentication using the protocol's state as the
  key.

Using these operations, one can construct a wide variety of symmetric-key constructions.

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2025 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
