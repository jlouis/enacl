# Erlang bindings for NaCl

This library provides bindings for the NaCl cryptographic library for Erlang. Several such libraries exist, but this one is a re-write with a number of different requirements, and foci:

* Erlang/OTP 17.3. This library *needs* the newest dirty scheduler implementation.
* Uses the original NaCl sources over something like libsodium. This is a deliberate choice.
* Tests created by aggressive use of Erlang QuickCheck.
* provides gen_nacl, a gen_tcp wrapper for sending/receiving messages over a tcp socket.

This package draws heavy inspiration from "erlang-nacl" by Tony Garnock-Jones.
