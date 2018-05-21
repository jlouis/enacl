# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.2]

### Fixed
- Work around `rebar3 hex` publishing .so files

## [0.17.1]

### Fixed
- Provide a fix for the `pwhash_str/x` functions. The C strings were
  not properly handled wrt. NULL-termination and what the libsodium
  library expects.

## [0.17.0]

### Added
- Expose the AEAD ChaCha20 Poly1305 (IETF) functionality (Hans
  Svensson / Quviq).
- Expose Curve25519 Scalar Multiplication over a base point in the
  curve (Hans Svensson / Quviq)
- Support the pwhash_* primitives (relying on Argon2) for password
  hashing (daveed-al / Venkatakumar Srinivasan)
- Support for EQC Mini runs (Irina Guberman). The generator doesn't
  inject faults, but it does verify the positive path. This is useful
  to verify the enacl library on embedded platforms and so on.
- Support generichash functions (Venkatakumar Srinivasan / Xaptum)

### Fixed
- The type specification of generichash/2 and generichash/3 was
  corrected (Technion)

### Changed
- Removed the experimental feature flag `ERL_NIF_DIRTY_JOB_CPU_BOUND`.
  This breaks compatibility with older Erlang releases of dirty
  schedulers, but prepares us correctly for the new releases where the
  dirty scheduler interface is on and enabled by default (YAZ!)
- Some `size_t` entries in the C layer are now `uint` (Zane Beckwith).
  The change only affects messages of exorbitant sizes, which we think
  should be guarded against anyway, and it fixes some obvious
  compilation problems on 32 bit architectures, and to boot matches
  better against the Erlang NIF interface. We might change this later,
  but hopefully this is a change for the better.

## [0.16.0]

Bump libsodium requirement to version 1.0.12. This gives us access to
a number of functions which are added recently and thus gives us
access to implement these from libsodium.

### Added

- Add kx_* functions (Alexander Malaev)
- chacha stream functions added, siphash-2-4 added, unsafe_memzero/1
  added (no attribution)

### Fixed
- Do not use the dirty-scheduler test macro as it is gone.

## [0.15.0]

### Fixed
- Using `enacl:sign_verify_detacted` on large iolists would fail to do
  the correct thing due to a typo. This has been corrected. Also the
  EQC tests have been extended to include large binary support to
  capture these kinds of errors in the future.

### Changed

- Many dirty-scheduler tunings have been performed to make sure we
  won't block a scheduler ever.
- New benchmarks: `bench/timing.erl` together with DTrace scripts
  `bench/*.d`
- Interface simplification toward the NIF api. Only execute
  instructions directly on the scheduler if the operation *really*
  benefits from doing so.

No functional change, but the above characteristic change may mean the
library now behaves differently from what it did before. It should be
a better citizen to other libraries and other parts of the system.

## [0.14.0]

### Added
- Add support for libsodiums `box_seal` functions (Amir Ghassemi Nasr)
- Add support for libsodiums `crypto_sign_detached` (Joel Stanley,
  Parnell Springmeyer)
### Changed
- Switch the tag names to the form `0.14.0` rather than `v0.14.0`. For
  this release both tags are present, but from the next release on, it
  won't be the case.

## [0.13.0]

### Fixed
- Quell warnings from the C code

### Added
- Add Ed 25519 utility API (Alexander Færøy)
- Add FreeBSD support for the NIF compilation (Ricardo Lanziano)

## [0.12.1]

### Changed
- Provide the `priv` directory for being able to properly build
  without manual intervention.

## [0.12.0]

### Added
- Introduce an extension interface for various necessary extensions to
  the eNaCl system for handling the Tor network, thanks to Alexander
  Færøy (ahf).
- Introduce Curve25519 manipulations into the extension interface.
- Write (rudimentary) QuickCheck tests for the new interface, to
  verify its correctness.

## [0.11.0]

### Added
- Introduce NIF layer beforenm/afternm calls.
- Introduce the API for precomputed keys (beforenm/afternm calls).
- Use test cases which tries to inject `iodata()` rather than binaries
  in all places where `iodata()` tend to be accepted.
### Fixed
- Fix type for `enacl:box_open/4`. The specification was wrong which
  results in errors in other applications using enacl.

## [0.10.2]

Maintenance release. Fix some usability problems with the library.

### Fixed
- Do not compile the C NIF code if there are no dirty scheduler
  support in the Erlang system (Thanks to David N. Welton)
- Fix dialyzer warnings (Thanks Anthony Ramine)
- Fix a wrong call in the timing code. Luckily, this error has not
  affected anything as it has only replaced a verification call with
  one that does not verify. In practice, the timing is roughly the
  same for both, save for a small constant factor (Thanks to the
  dialyzer)
- Improve documentation around installation/building the software.
  Hopefully it is now more prominent (Thanks to David N. Welton)

## [0.10.1]

### Added

- This small patch-release provides tests for the `randombytes/1`
function call, and optimizes EQC tests to make it easier to implement
`largebinary`-support in EQC tests.
- The release also adds an (experimental) scrambling function for
hiding the internal structure of counters. This is based on an
enlarged TEA-cipher by Wheeler and Needham. It is neccessary for
correct operation of the CurveCP implementation, which is why it is
included in this library.

## [0.10.0]

Ultra-late beta; tuning for the last couple of functions which could
be nice to have.

### Added

Added the function `randombytes/1` to obtain randombytes from the
operating system. The system uses the "best" applicable (P)RNG on the
target system:

* Windows: `RtlGenRandom()`
* OpenBSD, Bitrig: `arc4random()`
* Unix in general: `/dev/urandom`

Do note that on Linux and FreeBSD at the *least*, this is the best
thing you can do. Relying on `/dev/random` is almost always wrong and
gives no added security benefit. Key generation in NaCl relies on
`/dev/urandom`. Go relies on `/dev/urandom`. It is about time Erlang
does as well.

## [0.9.0]

Ultra-late beta. Code probably works, but it requires some real-world
use before it is deemed entirely stable.

Initial release.

