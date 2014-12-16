# Erlang bindings for NaCl

This library provides bindings for the NaCl cryptographic library for Erlang. Several such libraries exist, but this one is a re-write with a number of different requirements, and foci:

### INSTALL/Requirements:

* Erlang/OTP 17.3. This library *needs* the newest dirty scheduler implementation.
* Uses the libsodium sources. *Note:* libsodium is not in Debian/Ubuntu by default. You need to use something to handle the installation for you. E.g., `checkinstall` or `stow` are good tools for this. 

To build the software execute:

	make
	
or

	rebar compile

### Features:

* Complete library for every NaCl call, save `beforenm/afternm` invocations
* Implements a small set of additional functionality from libsodium. Most notably access to a proper CSPRNG random source
* Tests created by aggressive use of Erlang QuickCheck.

This package draws heavy inspiration from "erlang-nacl" by Tony Garnock-Jones.

In addition, I would like to thank Steve Vinoski, Rickard Green, and Sverker Eriksson for providing the Dirty Scheduler API in the first place.

# TODO

* Write simple correctness unit tests for the different NaCl primitives.
* Introduce `iodata()` and `eqc_gen:largebinary/2` support to test the code base for very large binaries and iodata input. The current test cases mostly concerns themselves about the rather small input.
* Verify that the binary-only inputs doesn't accept incorrect `iodata()` input.

# Versions

## v0.10.x

### v0.10.2

Maintenance release. Fix some usability problems with the library.

* Do not compile the C NIF code if there are no dirty scheduler support in the Erlang system (Thanks to David N. Welton)
* Fix dialyzer warnings (Thanks Anthony Ramine)
* Fix a wrong call in the timing code. Luckily, this error has not affected anything as it has only replaced a verification call with one that does not verify. In practice, the timing is roughly the same for both, save for a small constant factor (Thanks to the dialyzer)
* Improve documentation around installation/building the software. Hopefully it is now more prominent (Thanks to David N. Welton)

### v0.10.1

This small patch-release provides tests for the `randombytes/1` function call, and optimizes EQC tests to make it easier to implement `largebinary`-support in EQC tests. The release also adds an (experimental) scrambling function for hiding the internal structure of counters. This is based on an enlarged TEA-cipher by Wheeler and Needham. It is neccessary for correct operation of the CurveCP implementation, which is why it is included in this library.

### v0.10.0

Ultra-late beta; tuning for the last couple of functions which could be nice to have. Added the function `randombytes/1` to obtain randombytes from the operating system. The system uses the "best" applicable (P)RNG on the target system:

* Windows: `RtlGenRandom()`
* OpenBSD, Bitrig: `arc4random()`
* Unix in general: `/dev/urandom`

Do note that on Linux and FreeBSD at the *least*, this is the best thing you can do. Relying on `/dev/random` is almost always wrong and gives no added security benefit. Key generation in NaCl relies on `/dev/urandom`. Go relies on `/dev/urandom`. It is about time Erlang does as well.

## v0.9.x

Ultra-late beta. Code probably works, but it requires some real-world use before it is deemed entirely stable.

### v0.9.0

Initial release.

# Overview

The NaCl cryptographic library provides a number of different cryptographic primitives. In the following, we split up the different generic primitives and explain them briefly.

*A note on Nonces:* The crypto API makes use of "cryptographic nonces", that is arbitrary numbers which are used only once. For these primitives to be secure it is important to consult the NaCl documentation on their choice. They are large values so generating them randomly ensures security, provided the random number generator uses a sufficiently large period. If you end up using, say, the nonce `7` every time in communication while using the same keys, then the security falls.

The reason you can pick the nonce values is because some uses are better off using a nonce-construction based on monotonically increasing numbers, while other uses do not. The advantage of a sequence is that it can be used to reject older messages in the stream and protect against replay attacks. So the correct use is up to the application in many cases.

## Public Key cryptography

This implements standard Public/Secret key cryptography. The implementation roughly consists of two major sections:

* *Authenticated encryption:* provides a `box` primitive which encrypts and then also authenticates a message. The reciever is only able to open the sealed box if they posses the secret key and the authentication from the sender is correct.
* *Signatures:* allows one party to sign a message (not encrypting it) so another party can verify the message has the right origin.

## Secret key cryptography

This implements cryptography where there is a shared secret key between parties.

* *Authenticated encryption:* provides a `secret box` primitive in which we can encrypt a message with a shared key `k`. The box also authenticates the message, so a message with an invalid key will be rejected as well. This protects against the application obtaining garbage data.
* *Encryption:* provides streams of bytes based on a Key and a Nonce. These streams can be used to `XOR` with a message to encrypt it. No authentication is provided. The API allows for the system to `XOR` the message for you while producing the stream.
* *Authentication:* Provides an implementation of a Message Authentication Code (MAC).
* *One Time Authentication:* Authenticate a message, but do so one-time. That is, a sender may *never* authenticate several messages under the same key. Otherwise an attacker can forge authenticators with enough time. The primitive is simpler and faster than the MAC authenticator however, so it is useful in some situations.

## Low-level functions

* *Hashing:* Cryptographically secure hashing
* *String comparison:* Implements guaranteed constant-time string comparisons to protect against timing attacks.

# Rationale

Doing crypto right in Erlang is not that easy. For one, the crypto system has to be rather fast, which rules out Erlang as the main vehicle. Second, cryptographic systems must be void of timing attacks. This mandates we write the code in a language where we can avoid such timing attacks, which leaves only C as a contender, more or less. The obvious way to handle this is by the use of NIF implementations, but most C code will run to its conclusion once set off for processing. This is a major problem for a system which needs to keep its latency in check. The solution taken by this library is to use the new Dirty Scheduler API of Erlang in order to provide a safe way to handle the long-running cryptographic processing. It keeps the cryptographic primitives on the dirty schedulers and thus it avoids the major problem.

Focus has first and foremost been on the correct use of dirty schedulers, without any regard for speed. The plan is to extend the underlying implementation, while keeping the API stable. We can precompute keys for some operations for instance, which will yield a speedup.

Also, while the standard `crypto` bindings in Erlang does a great job at providing cryptographic primitives, these are based on OpenSSL, which is known to be highly problematic in many ways. It is not as easy to use the OpenSSL library correctly as it is with these bindings. Rather than providing a low-level cipher suite, NaCl provides intermediate level primitives constructed as to protect the user against typical low-level cryptographic gotchas and problems.

## Scheduler handling

To avoid long running NIFs, the library switches to the use of dirty schedulers for large encryption tasks. The target is roughly set at 1/10th of the 1ms budget at 100μs. That is, we have a threshold set such that work taking more than roughly 100μs will invoke the dirty scheduler. We currently care much more about the *progress* of the system rather than the *precision*. We care that another Erlang process gets to use the core so one process is unable to monopolize the scheduler thread. On the other hand, the price that a process pays to use encryption is something we care less about. A process may get a free ride or it may get penalized more than it should if it invokes crypto-code.

We currently use measurements to obtain some rough figures on the reduction counts different operations take. You can run these measurements by invoking:

	enacl_timing:all().
	
The current "typical modern machine" is:

	Intel Core i7-4900QM
	
When running benchmarks, we warm the CPU a bit before conducting the benchmark. Also, the script `benchmark.sh` can be used (altered to your CPU type), to disable the powersave mode of CPUs in order to obtain realistic benchmarks. Do note nothing was done to get a realistic disable of Intel's Turbo Boost functionality and this is a one-core benchmark. The numbers given are used as an input to the reduction budget. If a task takes roughly 134μs we assume it costs `134*2` reductions.

I'm interested in machines for which the schedules end up being far off. That is, machines for which the current CPU schedule takes more than 250μs. This is especially interesting for virtual machines, and machines with ARM cores. If you are running on very slow machines, you may have to tune the reduction counts and threshold sizes to get good latency on the system.

# Testing

Every primitive has been stress-tested through the use of Erlang QuickCheck with both *positive* and *negative* testing. This has been used to check against memory leaks as well as correct invocation. Please report any error so we can extend the test cases to include a randomized test which captures the problem so we generically catch every problem in a given class of errors.

Positive and negative testing refers to Type I and Type II errors in statistical testing. This means false positives—given a *valid* input the function rejects it; as well as false negatives—given an *invalid* input the functions fails to reject that input.

The problem however, is that while we are testing the API level, we can't really test the strength of the cryptographic primitives. We can verify their correctness by trying different standard correctness tests for the primitives, verifying that the output matches the expected one given a specific input. But there is no way we can show that the cryptographic primitive has the strength we want. Thus, we opted to mostly test the API and its invocation for stability.

Also, in addition to correctness, testing the system like this makes sure we have no memory leaks as they will show themselves under the extensive QuickCheck test cases we run. It has been verified there are no leaks in the code.

