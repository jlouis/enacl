# Erlang bindings for NaCl

This library provides bindings for the NaCl cryptographic library for Erlang. Several such libraries exist, but this one is a re-write with a number of different requirements, and foci:

* Erlang/OTP 17.3. This library *needs* the newest dirty scheduler implementation.
* Uses the libsodium sources. This is a deliberate choice, since it is easy to implement.
* Does not provide anything but the original NaCl code base. This is also a deliberate choice so we are not in a situation where we can't jump to a newer version of the library later at some point.
* Tests created by aggressive use of Erlang QuickCheck.

This package draws heavy inspiration from "erlang-nacl" by Tony Garnock-Jones.

# Rationale

Doing crypto right in Erlang is not that easy. The obvious way to handle this is by the use of NIF implementations, but most C code will run to its conclusion once set off for processing. This is a major problem for a system which needs to keep its latency safe. The solution taken by this library is to use the new Dirty Scheduler API of Erlang in order to provide a safe way to handle the long-running cryptographic processing. It keeps the cryptographic primitives on the dirty schedulers and thus it avoids the major problem.

