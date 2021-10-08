# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.2.1]

### Fixed [1.2.1]

- Export types from the `enacl` module so it can be referenced in other parts of your system (serokell.io)

## [1.2.0]

### Fixed [1.2.0]

- `sign_verify_detached/3` The code now verifies the size of signatures in detached mode. Before
  this change, you could supply a larger binary and the code would only use the first `SIGNBYTES`
  of the binary, assuming the signature were in there. Now, it fails with a badarg if the signature
  doesn't match expectation in size.

## [1.1.1]

### Added [1.1.1]

- Introduce the ability to reload the enacl module (Bryan Paxton, @starbelly)

## [1.1.0]

### Added [1.1.0]

- Secretstream support was added to the API (Alexander Malaev)
- Add KDF functions (Nicolas Goy, @kuon)
- Add pwhash/5 specifying what algorithm to use for older compatibility (Nicolas Goy, @kuon)

### Changed [1.1.0]

- Remove rebar3_hex as a direct dependency (Bryan Paxton, @starbelly)

## [1.0.0]

### Compatibility [1.0.0]

- Some functions have been streamlined to badarg in certain cases where it made more
  sense to do so than returning back an error to the caller.
- Functions generally don't return error values for internal errors. They now raise
  exceptions when this happens. If you can't allocate a binary, there is usually not
  much the programmer can do with that information, sans crashing.
- If you used `aead_chacha20poly1305_*` functions, please read through the changelog
  carefully as we have made changes to these functions. TL;DR: look for
  `aead_chacha20poly1305_ietf_*` but note it is *not* just a simple substitution
  into your code.
- The `kx` constants have been renamed to follow libsodium one-to-one.
- All calls with `verify` now returns booleans. See `sign_verify_detached`, which
  were changed by this.
- Many constants were changed to their underlying libsodium names.

### Removed [1.0.0]

- The functions of the form `aead_chacha20poly1305_*` were removed. They implement
  the IETF variant, and the argument order for them were wrong. Also, they used
  severely limited nonce values, which is somewhat dangerous. The `..._NONCEBYTES`
  name was changed to the consistent `..._NPUBBYTES`.

### Added [1.0.0]

- Added `aead_chacha20poly1305_ietf_*` variants.
- Implement multipart signature support, by Garry Hill.
- Implement enacl:crypto_sign_seed_keypair/1, by Ole Andre Birkedal.
- Implement enacl:crypto_sign_ed25519_sk_to_pk/1, by an anonymous contribution.
- Added AEAD XChaCha20-Poly1305 support, thanks to Github/ECrownofFire.
- The Password Hash Generation functions now support memory and operations limits,
  thanks to Github/ECrownofFire.
- Implement enacl:randombytes_uint32/0. Returns a random 32bit unsigned
  integer, by means of the underlying random source.
- Implement enacl:randombytes_uniform/1. Takes up to a 32bit unsigned
  integer and produces a uniform integer in the range [0..N). Note
  that the implementation avoids the typical non-uniformness which
  would be present on a modulus operation on the nearest power-of-two
  integer.
- Added Win32 build support (Tino Breddin)
- Added a nix shell for easier development

### Changed [1.0.0]

- Started a split the C code over multiple files for easier maintenance.
- Rewrote the generichash routines to be more consistent. We are now more-or-less
  following the style of the Erlang/OTP `crypto` library. While here, make sure
  we clean up correctly and that we don't accidentally mis-ref-count data. The
  code is a bit more goto heavy, but this style is surprisingly common in C code.
- Use sodium's dynamic memory allocators. These guarantee 64bit alignment, and also
  provide guard pages around the allocation, somewhat protecting it. It adds some
  page table pressure compared to the current code, but is easier to maintain and
  much cleaner code.
- The code now rejects updates to generichash states which were already finalized.
- We now track the desired outlen of a generichash operation in the opaque NIF
  resource rather than on the Erlang side. This avoids some checks in the code,
  and streamlines a good deal of the interface.
- Split AEAD routines off from the main enacl_nif.c file
- Renamed many routines from enif_* to enacl_*. This better reflects where they live
  in the code base, and avoids pollution of the enif_* "namespace".
- Split Sign Public Key routines from the rest. Modernize the handling of contexts.
- The multi-part generic hash routines now follow the structure of the crypto
  modules multi-part constructions in API and style.
- The AEAD constructions have been streamlined so they follow the rules of libsodium
  closer than before. In particular, some dead code has been removed as a result.
- Constants are now named by their libsodium counterpart. This should make it easier
  to find the correct names given the libsodium documentation.
- Generichash now checks if a `_final` call has already happened and rejects further
  hashing on the object. The rejection is an error: if you ever do this, your code
  is definitely wrong and there is no recovery possible.

### Fixed [1.0.0]

- Fix a resource leak in generichash/sign init/update/final.
- Clang static analysis warnings (Thomas Arts).
- Replace a constant 31 with a computation from libsodium (Thomas Arts, from a security review).
- Some subtle memory leaks in the error path for kx operations were plugged.
- The multi-part generichash interface is now properly process/thread safe.
- The sign interface is now properly process/thread safe.

## [0.17.2]

### Fixed [0.17.2]

- Work around `rebar3 hex` publishing .so files

## [0.17.1]

### Fixed [0.17.1]

- Provide a fix for the `pwhash_str/x` functions. The C strings were
  not properly handled wrt. NULL-termination and what the libsodium
  library expects.

## [0.17.0]

### Added [0.17.0]

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

### Fixed [0.17.0]

- The type specification of generichash/2 and generichash/3 was
  corrected (Technion)

### Changed [0.17.0]

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

### Added [0.16.0]

- Add kx_* functions (Alexander Malaev)
- chacha stream functions added, siphash-2-4 added, unsafe_memzero/1
  added (no attribution)

### Fixed [0.16.0]

- Do not use the dirty-scheduler test macro as it is gone.

## [0.15.0]

### Fixed [0.15.0]

- Using `enacl:sign_verify_detacted` on large iolists would fail to do
  the correct thing due to a typo. This has been corrected. Also the
  EQC tests have been extended to include large binary support to
  capture these kinds of errors in the future.

### Changed [0.15.0]

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

### Added [0.14.0]

- Add support for libsodiums `box_seal` functions (Amir Ghassemi Nasr)
- Add support for libsodiums `crypto_sign_detached` (Joel Stanley,
  Parnell Springmeyer)

### Changed [0.14.0]

- Switch the tag names to the form `0.14.0` rather than `v0.14.0`. For
  this release both tags are present, but from the next release on, it
  won't be the case.

## [0.13.0]

### Fixed [0.13.0]

- Quell warnings from the C code

### Added [0.13.0]

- Add Ed 25519 utility API (Alexander Færøy)
- Add FreeBSD support for the NIF compilation (Ricardo Lanziano)

## [0.12.1]

### Changed [0.12.1]

- Provide the `priv` directory for being able to properly build
  without manual intervention.

## [0.12.0]

### Added [0.12.0]

- Introduce an extension interface for various necessary extensions to
  the eNaCl system for handling the Tor network, thanks to Alexander
  Færøy (ahf).
- Introduce Curve25519 manipulations into the extension interface.
- Write (rudimentary) QuickCheck tests for the new interface, to
  verify its correctness.

## [0.11.0]

### Added [0.11.0]

- Introduce NIF layer beforenm/afternm calls.
- Introduce the API for precomputed keys (beforenm/afternm calls).
- Use test cases which tries to inject `iodata()` rather than binaries
  in all places where `iodata()` tend to be accepted.

### Fixed [0.11.0]

- Fix type for `enacl:box_open/4`. The specification was wrong which
  results in errors in other applications using enacl.

## [0.10.2]

Maintenance release. Fix some usability problems with the library.

### Fixed [0.10.2]

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

### Added [0.10.1]

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

### Added [0.10.0]

Added the function `randombytes/1` to obtain randombytes from the
operating system. The system uses the "best" applicable (P)RNG on the
target system:

- Windows: `RtlGenRandom()`
- OpenBSD, Bitrig: `arc4random()`
- Unix in general: `/dev/urandom`

Do note that on Linux and FreeBSD at the *least*, this is the best
thing you can do. Relying on `/dev/random` is almost always wrong and
gives no added security benefit. Key generation in NaCl relies on
`/dev/urandom`. Go relies on `/dev/urandom`. It is about time Erlang
does as well.

## [0.9.0]

Ultra-late beta. Code probably works, but it requires some real-world
use before it is deemed entirely stable.

Initial release.
