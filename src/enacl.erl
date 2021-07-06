%%% @doc Module enacl implements bindings to the NaCl/libsodium crypto-library
%%% <p>This module implements NIF bindings to the library known as NaCl (pronounced "salt").
%%% The NaCl library provides a sane cryptographic interface to the world in an attempt to
%%% make it harder to abuse and misuse cryptographic primitives.</p>
%%% <p>This module implements an Erlang-idiomatic API to the underlying library. If in doubt
%%% about a primitive, always consult the underlying documentation.</p>
%%% <p>There are two libraries in existence: NaCl and libsodium, the latter being a more
%%% portable variant of the NaCl library. The C-level API is interchangeable so we can run
%%% on any of these underlying libraries as seen from the Erlang world. We simply have to
%%% restrict ourselves to the portion of the code base which is overlapping.</p>
%%% <p><b>Warning:</b> It is necessary to apply the primitives here correctly. Wrong
%%% application may result in severely reduced strength of the cryptography. Take some
%%% time to make sure this is the case before using.</p>
%%% <p><b>Note:</b> All functions will fail with a `badarg' error if given incorrect
%%% parameters. Also, if something is wrong internally, they will raise an error of
%%% the form `enacl_internal_error'. There is usually no way to continue gracefully
%%% from either of these. A third error is `enacl_finalized', raised when you try
%%% re-using an already finalized state for multi-part messages.</p>
%%% @end.
-module(enacl).

%% Public key crypto
-export([
         %% EQC
         box_keypair/0,
         box/4,
         box_open/4,
         box_beforenm/2,
         box_afternm/3,
         box_open_afternm/3,
         box_NONCEBYTES/0,
         box_PUBLICKEYBYTES/0,
         box_SECRETKEYBYTES/0,
         box_BEFORENMBYTES/0,

         sign_PUBLICBYTES/0,
         sign_SECRETBYTES/0,
         sign_SEEDBYTES/0,
         sign_keypair/0,
         sign_seed_keypair/1,
         sign/2,
         sign_open/2,
         sign_detached/2,
         sign_verify_detached/3,

         sign_init/0,
         sign_update/2,
         sign_final_create/2,
         sign_final_verify/3,

         box_seal/2,
         box_seal_open/3
]).

%% Secret key crypto
-export([
         %% EQC
         secretbox_KEYBYTES/0,
         secretbox_NONCEBYTES/0,
         secretbox/3,
         secretbox_open/3,

         %% No Tests!
         stream_chacha20_KEYBYTES/0,
         stream_chacha20_NONCEBYTES/0,
         stream_chacha20/3,
         stream_chacha20_xor/3,

         %% EQC
         aead_chacha20poly1305_ietf_encrypt/4,
         aead_chacha20poly1305_ietf_decrypt/4,
         aead_chacha20poly1305_ietf_KEYBYTES/0,
         aead_chacha20poly1305_ietf_NPUBBYTES/0,
         aead_chacha20poly1305_ietf_ABYTES/0,
         aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX/0,

         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4,
         aead_xchacha20poly1305_ietf_KEYBYTES/0,
         aead_xchacha20poly1305_ietf_NPUBBYTES/0,
         aead_xchacha20poly1305_ietf_ABYTES/0,
         aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX/0,

         %% EQC
         stream_KEYBYTES/0,
         stream_NONCEBYTES/0,
         stream/3,

         %% No Tests!
         stream_xor/3,

         %% EQC
         auth_KEYBYTES/0,
         auth_BYTES/0,
         auth/2,
         auth_verify/3,

         %% EQC
         onetime_auth_KEYBYTES/0,
         onetime_auth_BYTES/0,
         onetime_auth/2,
         onetime_auth_verify/3
]).

%% Hash functions
-export([
         %% No Tests!
         generichash/3,
         generichash/2,
         generichash_init/2,
         generichash_update/2,
         generichash_final/1,

         %% EQC!
         shorthash_key_size/0,
         shorthash_size/0,
         shorthash/2,

         pwhash_SALTBYTES/0,
         pwhash/2,
         pwhash/4,
         pwhash/5,
         pwhash_str/1,
         pwhash_str/3,
         pwhash_str_verify/2

]).

%% Key derivation
-export([
         kdf_KEYBYTES/0,
         kdf_CONTEXTBYTES/0,
         kdf_derive_from_key/3
]).

%% Low-level subtle functions which are hard to get correct
-export([
         %% EQC
         hash/1,
         verify_16/2,
         verify_32/2,

         %% No Tests!
         unsafe_memzero/1
]).

%% Randomness
-export([
         %% EQC
         randombytes/1,
         randombytes_uint32/0,
         randombytes_uniform/1
]).

%%% Specific primitives
%% Curve 25519 operations.
-export([
         %% No Tests!
         curve25519_scalarmult/1, curve25519_scalarmult/2,
         curve25519_scalarmult_base/1
]).

%% Ed 25519 operations.
-export([
         %% No Tests!
         crypto_sign_ed25519_keypair/0,
         crypto_sign_ed25519_sk_to_pk/1,
         crypto_sign_ed25519_public_to_curve25519/1,
         crypto_sign_ed25519_secret_to_curve25519/1,
         crypto_sign_ed25519_public_size/0,
         crypto_sign_ed25519_secret_size/0
        ]).

%% Key exchange functions
-export([
         %% EQC
         kx_keypair/0,
         kx_client_session_keys/3,
         kx_server_session_keys/3,
         kx_PUBLICKEYBYTES/0,
         kx_SECRETKEYBYTES/0,
         kx_SESSIONKEYBYTES/0
]).

%% Secretstream operations.
-export([
         %% Unit tests
         secretstream_xchacha20poly1305_ABYTES/0,
         secretstream_xchacha20poly1305_HEADERBYTES/0,
         secretstream_xchacha20poly1305_KEYBYTES/0,
         secretstream_xchacha20poly1305_MESSAGEBYTES_MAX/0,
         secretstream_xchacha20poly1305_TAG_MESSAGE/0,
         secretstream_xchacha20poly1305_TAG_PUSH/0,
         secretstream_xchacha20poly1305_TAG_REKEY/0,
         secretstream_xchacha20poly1305_TAG_FINAL/0,
         secretstream_xchacha20poly1305_keygen/0,
         secretstream_xchacha20poly1305_init_push/1,
         secretstream_xchacha20poly1305_push/4,
         secretstream_xchacha20poly1305_init_pull/2,
         secretstream_xchacha20poly1305_pull/3,
         secretstream_xchacha20poly1305_rekey/1
        ]).

%% Internal verification of the system
-export([verify/0]).

%% Type specifications
-type generichash_bytes() :: 10..64.
-type sign_state() :: reference().

-type pwhash_alg() :: default | argon2i13 | argon2id13 | pos_integer().
-type pwhash_limit() :: interactive | moderate | sensitive | pos_integer().
-type secretstream_xchacha20poly1305_tag() :: message | rekey | final | push | pos_integer().

-export_type([
    generichash_bytes/0,
    pwhash_alg/0,
    pwhash_limit/0,
    secretstream_xchacha20poly1305_tag/0,
    sign_state/0
]).



%% Definitions of system budgets
%% To get a grip for these, call `enacl_timing:all/0' on your system. The numbers here are
%% described in the README.md file.
-define(HASH_SIZE, 4 * 1024).
-define(HASH_REDUCTIONS, 17 * 2).
-define(BOX_BEFORENM_REDUCTIONS, 60).
-define(BOX_AFTERNM_SIZE, 8 * 1024).
-define(BOX_AFTERNM_REDUCTIONS, 17 * 2).
-define(SECRETBOX_SIZE, 8 * 1024).
-define(SECRETBOX_REDUCTIONS, 17 * 2).
-define(SECRETBOX_OPEN_REDUCTIONS, 17 * 2).
-define(STREAM_SIZE, 16 * 1024).
-define(STREAM_REDUCTIONS, 17 * 2).
-define(auth_BYTES, 4 * 1024).
-define(AUTH_REDUCTIONS, 17 * 2).
-define(ONETIME_auth_BYTES, 16 * 1024).
-define(ONETIME_AUTH_REDUCTIONS, 16 * 2).
-define(ED25519_PUBLIC_TO_CURVE_REDS, 20 * 2).
-define(ED25519_SECRET_TO_CURVE_REDS, 20 * 2).

%% Constants used throughout the code base
-define(CRYPTO_BOX_ZEROBYTES, 32).
-define(P_ZEROBYTES, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>). %% 32 bytes of 0
-define(CRYPTO_BOX_BOXZEROBYTES, 16).
-define(P_BOXZEROBYTES, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>).  %% 16 bytes

-define(CRYPTO_SECRETBOX_ZEROBYTES, 32).
-define(S_ZEROBYTES, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>). %% 32 bytes
-define(CRYPTO_SECRETBOX_BOXZEROBYTES, 16).
-define(S_BOXZEROBYTES, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>). %% 16 bytes
-define(CRYPTO_STREAM_CHACHA20_KEYBYTES, 32).
-define(CRYPTO_STREAM_CHACHA20_NONCEBYTES, 8).
-define(CRYPTO_STREAM_KEYBYTES, 32).
-define(CRYPTO_STREAM_NONCEBYTES, 24).
-define(CRYPTO_KX_PUBLICKEYBYTES, 32).
-define(CRYPTO_KX_SECRETKEYBYTES, 32).
-define(CRYPTO_KX_SESSIONKEYBYTES, 32).

-define(CRYPTO_GENERICHASH_BYTES_MIN, 16).
-define(CRYPTO_GENERICHASH_BYTES_MAX, 64).
-define(CRYPTO_GENERICHASH_BYTES, 32).
-define(CRYPTO_GENERICHASH_KEYBYTES_MIN, 16).
-define(CRYPTO_GENERICHASH_KEYBYTES_MAX, 64).
-define(CRYPTO_GENERICHASH_KEYBYTES, 32).

-define(CRYPTO_SECRETSTREAM_TAG_MESSAGE, 0).
-define(CRYPTO_SECRETSTREAM_TAG_PUSH, 1).
-define(CRYPTO_SECRETSTREAM_TAG_REKEY, 2).
-define(CRYPTO_SECRETSTREAM_TAG_FINAL, 3).

%% Size limits
-define(MAX_32BIT_INT, 1 bsl 32).

%% @doc Verify makes sure the constants defined in libsodium matches ours
verify() ->
    true = equals(binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()), ?P_ZEROBYTES),
    true = equals(binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()), ?P_BOXZEROBYTES),
    true = equals(binary:copy(<<0>>, enacl_nif:crypto_secretbox_ZEROBYTES()), ?S_ZEROBYTES),
    true = equals(binary:copy(<<0>>, enacl_nif:crypto_secretbox_BOXZEROBYTES()),
                  ?S_BOXZEROBYTES),

    Verifiers =
        [
         {crypto_stream_chacha20_KEYBYTES, ?CRYPTO_STREAM_CHACHA20_KEYBYTES},
         {crypto_stream_chacha20_NONCEBYTES, ?CRYPTO_STREAM_CHACHA20_NONCEBYTES},
         {crypto_stream_KEYBYTES, ?CRYPTO_STREAM_KEYBYTES},
         {crypto_stream_NONCEBYTES, ?CRYPTO_STREAM_NONCEBYTES},
         {crypto_box_ZEROBYTES, ?CRYPTO_BOX_ZEROBYTES},
         {crypto_box_BOXZEROBYTES, ?CRYPTO_BOX_BOXZEROBYTES},
         {crypto_secretbox_ZEROBYTES, ?CRYPTO_SECRETBOX_ZEROBYTES},
         {crypto_secretbox_BOXZEROBYTES, ?CRYPTO_SECRETBOX_BOXZEROBYTES},
         {crypto_kx_SESSIONKEYBYTES, ?CRYPTO_KX_SESSIONKEYBYTES},
         {crypto_kx_PUBLICKEYBYTES, ?CRYPTO_KX_PUBLICKEYBYTES},
         {crypto_kx_SECRETKEYBYTES, ?CRYPTO_KX_SECRETKEYBYTES},
         {crypto_generichash_BYTES, ?CRYPTO_GENERICHASH_BYTES},
         {crypto_generichash_BYTES_MIN, ?CRYPTO_GENERICHASH_BYTES_MIN},
         {crypto_generichash_BYTES_MAX, ?CRYPTO_GENERICHASH_BYTES_MAX},
         {crypto_generichash_KEYBYTES, ?CRYPTO_GENERICHASH_KEYBYTES},
         {crypto_generichash_KEYBYTES_MIN, ?CRYPTO_GENERICHASH_KEYBYTES_MIN},
         {crypto_generichash_KEYBYTES_MAX, ?CRYPTO_GENERICHASH_KEYBYTES_MAX},
         {crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, ?CRYPTO_SECRETSTREAM_TAG_MESSAGE},
         {crypto_secretstream_xchacha20poly1305_TAG_PUSH, ?CRYPTO_SECRETSTREAM_TAG_PUSH},
         {crypto_secretstream_xchacha20poly1305_TAG_REKEY, ?CRYPTO_SECRETSTREAM_TAG_REKEY},
         {crypto_secretstream_xchacha20poly1305_TAG_FINAL, ?CRYPTO_SECRETSTREAM_TAG_FINAL}
    ],
    run_verifiers(Verifiers).

run_verifiers([]) -> ok;
run_verifiers([{V, R} | Vs]) ->
    case enacl_nif:V() of
        R -> run_verifiers(Vs);
        Other -> {error, {verifier, V, {R, '/=', Other}}}
    end.

equals(X,X) -> true;
equals(X,Y) -> {X, '/=', Y}.

%% Low level helper functions
%% -----------------

%% @doc hash/1 hashes data into a cryptographically secure checksum.
%%
%% <p>Given an iodata(), `Data' of any size, run a cryptographically secure hash algorithm to
%% produce a checksum of the data. This can be used to verify the integrity of a data block
%% since the checksum have the properties of cryptographic hashes in general.</p>
%% <p>The currently selected primitive (Nov. 2014) is SHA-512</p>
%% @end
-spec hash(Data) -> Checksum
    when
      Data :: iodata(),
      Checksum :: binary().
hash(Bin) ->
    case iolist_size(Bin) of
        K when K =< ?HASH_SIZE ->
            bump(enacl_nif:crypto_hash_b(Bin), ?HASH_REDUCTIONS, ?HASH_SIZE, K);
        _ ->
            enacl_nif:crypto_hash(Bin)
    end.

%% @doc verify_16/2 implements constant time 16-byte binary() verification
%%
%% <p>A subtle problem in cryptographic software are timing attacks where an attacker exploits
%% early exist in string verification if the strings happen to mismatch. This allows the
%% attacker to time how long verification took and thus learn the structure of the desired
%% string to use. The verify_16/2 call will check two 16 byte strings for equality while
%% guaranteeing the equality operation is constant time.</p>
%% <p>If the strings are not exactly 16 bytes, the comparison function will fail with badarg.</p>
%% <p>The functions take binary() values and not iolist() values since the latter would convert in non-constant time</p>
%% <p>Verification returns a boolean. `true' if the strings match, `false' otherwise.</p>
%% @end
-spec verify_16(binary(), binary()) -> boolean().
verify_16(X, Y) when is_binary(X), is_binary(Y) ->
    enacl_nif:crypto_verify_16(X, Y);
verify_16(_, _) ->
    error(badarg).

%% @doc verify_32/2 implements constant time 32-byte iolist() verification
%%
%% This function works as {@link verify_16/2} but does so on 32 byte strings. Same caveats apply.
%% @end
-spec verify_32(binary(), binary()) -> boolean().
verify_32(X, Y) when is_binary(X), is_binary(Y) ->
    enacl_nif:crypto_verify_32(X, Y);
verify_32(_, _) ->
    error(badarg).

%% @doc unsafe_memzero/1 ipmlements guaranteed zero'ing of binary data.
%%
%% <p><bold>WARNING:</bold> Take great care. This way be dragons.</p>
%% <p>This is verify unsafe. If any copies of the binary have been made they are unaffected.
%% This is intended for use with cryptographic keys where they are only shared within
%% a running process without copies. This allows removing, eg, symmetric session keys. </p>
%% @end
-spec unsafe_memzero(binary()) -> atom().
unsafe_memzero(X) when is_binary(X) ->
    enacl_nif:sodium_memzero(X);
unsafe_memzero(_) ->
    error(badarg).


%% @doc generichash/3 creates a hash of the message using a key.
%%
%% This function generates a hash of the message using a key. The hash size is
%% either 16, 32 or 64 bytes
%% @end
-spec generichash(generichash_bytes(), iodata(), binary()) -> binary().
generichash(HashSize, Message, Key) ->
    enacl_nif:crypto_generichash(HashSize, Message, Key).

%% @doc generichash/2 creates a hash of the message.
%%
%% This function generates a hash of the message. The hash size is
%% either 16, 32 or 64 bytes
%% @end
-spec generichash(generichash_bytes(), iodata()) -> binary().
generichash(HashSize, Message) ->
    enacl_nif:crypto_generichash(HashSize, Message, <<>>).

%% @doc generichash_init/2 initializes a multi-part hash.
%% @end
-spec generichash_init(generichash_bytes(), binary()) -> reference().
generichash_init(HashSize, Key) ->
    enacl_nif:crypto_generichash_init(HashSize, Key).

%% @doc generichash_update/2 updates a multi-part hash with new data.
%% @end
-spec generichash_update(reference(), iodata()) -> reference().
generichash_update(State, Message) ->
    enacl_nif:crypto_generichash_update(State, Message).

%% @doc generichash_final/1 finalizes a multi-part hash.
-spec generichash_final(reference()) -> binary().
generichash_final(State) ->
    enacl_nif:crypto_generichash_final(State).

%% @doc pwhash_SALTBYTES/0 returns the number of bytes required for salt.
%% @end
-spec pwhash_SALTBYTES() -> pos_integer().
pwhash_SALTBYTES() ->
    enacl_nif:crypto_pwhash_SALTBYTES().

%% @doc pwhash/2 hash a password
%%
%% This function generates a fixed size salted hash of a user defined password.
%% Defaults to interactive/interactive limits.
%% @end
-spec pwhash(iodata(), binary()) -> binary().
pwhash(Password, Salt) ->
    pwhash(Password, Salt, interactive, interactive).

%% @doc pwhash/4 hash a password
%%
%% This function generates a fixed size salted hash of a user defined password given Ops and Mem
%% limits.
%% @end
-spec pwhash(Password, Salt, Ops, Mem) -> binary()
    when
      Password :: iodata(),
      Salt     :: binary(),
      Ops      :: pwhash_limit(),
      Mem      :: pwhash_limit().
pwhash(Password, Salt, Ops, Mem) ->
    enacl_nif:crypto_pwhash(Password, Salt, Ops, Mem, default).

%% @doc pwhash/5 hash a password
%%
%% This function generates a fixed size salted hash of a user defined password given Ops and Mem
%% limits.
%% @end
-spec pwhash(Password, Salt, Ops, Mem, Alg) -> binary()
    when
      Password :: iodata(),
      Salt     :: binary(),
      Ops      :: pwhash_limit(),
      Mem      :: pwhash_limit(),
      Alg      :: pwhash_alg().
pwhash(Password, Salt, Ops, Mem, Alg) ->
    enacl_nif:crypto_pwhash(Password, Salt, Ops, Mem, Alg).

%% @doc pwhash_str/1 generates a ASCII encoded hash of a password
%%
%% This function generates a fixed size, salted, ASCII encoded hash of a user defined password.
%% Defaults to interactive/interactive limits.
%% @end
-spec pwhash_str(iodata()) -> iodata().
pwhash_str(Password) ->
    pwhash_str(Password, interactive, interactive).

%% @doc pwhash_str/3 generates a ASCII encoded hash of a password
%%
%% This function generates a fixed size, salted, ASCII encoded hash of a user defined password
%% given Ops and Mem limits.
%% @end
-spec pwhash_str(Password, Ops, Mem) -> iodata()
    when
      Password :: iodata(),
      Ops :: pwhash_limit(),
      Mem :: pwhash_limit().
pwhash_str(Password, Ops, Mem) ->
    strip_null_terminate(enacl_nif:crypto_pwhash_str(Password, Ops, Mem)).

strip_null_terminate(Binary) ->
    [X, _] = binary:split(Binary, <<0>>),
    X.

null_terminate(ASCII) ->
    iolist_to_binary([ASCII, 0]).

%% @doc pwhash_str_verify/2 compares a password with a hash
%%
%% This function verifies that the hash is generated from the password. The
%% function returns true if the verifcate succeeds, false otherwise
%% @end
-spec pwhash_str_verify(binary(), iodata()) -> boolean().
pwhash_str_verify(HashPassword, Password) ->
    enacl_nif:crypto_pwhash_str_verify(null_terminate(HashPassword), Password).

%% Key Derivation
%% @doc kdf_KEYBYTES/0 returns the number of bytes required for master key.
%% @end
-spec kdf_KEYBYTES() -> pos_integer().
kdf_KEYBYTES() ->
    enacl_nif:crypto_kdf_KEYBYTES().

%% @doc kdf_CONTEXTBYTES/0 returns the number of bytes required for context.
%% @end
-spec kdf_CONTEXTBYTES() -> pos_integer().
kdf_CONTEXTBYTES() ->
    enacl_nif:crypto_kdf_CONTEXTBYTES().

%% @doc kdf_derive_from_key/3 derive a key from a single high entropy key
%% @end.
-spec kdf_derive_from_key(MasterKey, Context, Id) -> binary()
    when
      MasterKey :: iodata(),
      Context   :: binary(),
      Id        :: pos_integer().
kdf_derive_from_key(MasterKey, Context, Id) ->
    enacl_nif:crypto_kdf_derive_from_key(MasterKey, Context, Id).

%% Public Key Crypto
%% ---------------------
%% @doc box_keypair/0 creates a new Public/Secret keypair.
%%
%% Generates and returns a new key pair for the Box encryption scheme. The return value is a
%% map in order to avoid using the public key as a secret key and vice versa.
%% @end.
-spec box_keypair() -> #{ atom() => binary() }.
box_keypair() ->
    {PK, SK} = enacl_nif:crypto_box_keypair(),
    #{ public => PK, secret => SK}.


%% @doc box/4 encrypts+authenticates a message to another party.
%%
%% Encrypt a `Msg' to the party identified by public key `PK' using your own secret key `SK' to
%% authenticate yourself. Requires a `Nonce' in addition. Returns the ciphered message.
%% @end
-spec box(Msg, Nonce, PK, SK) -> CipherText
    when
      Msg :: iodata(),
      Nonce :: binary(),
      PK :: binary(),
      SK :: binary(),
      CipherText :: binary().
box(Msg, Nonce, PK, SK) ->
    enacl_nif:crypto_box([?P_ZEROBYTES, Msg], Nonce, PK, SK).

%% @doc box_open/4 decrypts+verifies a message from another party.
%%
%% Decrypt a `CipherText' into a `Msg' given the other partys public key `PK' and your secret
%% key `SK'. Also requires the same nonce as was used by the other party. Returns the plaintext
%% message.
%% @end
-spec box_open(CipherText, Nonce, PK, SK) -> {ok, Msg} | {error, failed_verification}
    when
      CipherText :: iodata(),
      Nonce :: binary(),
      PK :: binary(),
      SK :: binary(),
      Msg :: binary().
box_open(CipherText, Nonce, PK, SK) ->
    enacl_nif:crypto_box_open([?P_BOXZEROBYTES, CipherText], Nonce, PK, SK).

%% @doc box_beforenm/2 precomputes a box shared key for a PK/SK keypair
%% @end
-spec box_beforenm(PK, SK) -> binary()
    when
      PK :: binary(),
      SK :: binary().
box_beforenm(PK, SK) ->
    R = enacl_nif:crypto_box_beforenm(PK, SK),
    erlang:bump_reductions(?BOX_BEFORENM_REDUCTIONS),
    R.

%% @doc box_afternm/3 works like `box/4' but uses a precomputed key
%%
%% Calling `box_afternm(M, Nonce, K)' for a precomputed key `K = box_beforenm(PK, SK)' works exactly as
%% if you had called `box(M, Nonce, PK, SK)'. Except that it avoids computations in the elliptic curve Curve25519,
%% and thus is a much faster operation.
%% @end
-spec box_afternm(Msg, Nonce, K) -> CipherText
    when
      Msg :: iodata(),
      Nonce :: binary(),
      K :: binary(),
      CipherText :: binary().
box_afternm(Msg, Nonce, Key) ->
    case iolist_size(Msg) of
        K when K =< ?BOX_AFTERNM_SIZE ->
            bump(enacl_nif:crypto_box_afternm_b([?P_ZEROBYTES, Msg], Nonce, Key),
                 ?BOX_AFTERNM_REDUCTIONS, ?BOX_AFTERNM_SIZE, K);
        _ ->
            enacl_nif:crypto_box_afternm([?P_ZEROBYTES, Msg], Nonce, Key)
    end.

%% @doc box_open_afternm/3 works like `box_open/4` but uses a precomputed key
%%
%% Calling `box_open_afternm(M, Nonce, K)' for a precomputed key `K = box_beforenm(PK, SK)' works exactly as
%% if you had called `box_open(M, Nonce, PK, SK)'. Except the operation is much faster as it avoids costly
%% computations in the elliptic curve Curve25519.
%% @end
-spec box_open_afternm(CT, Nonce, K) -> {ok, Msg} | {error, failed_verification}
    when
      CT :: binary(),
      Nonce :: binary(),
      K :: binary(),
      Msg :: binary().
box_open_afternm(CipherText, Nonce, Key) ->
    case iolist_size(CipherText) of
        K when K =< ?BOX_AFTERNM_SIZE ->
            R = enacl_nif:crypto_box_open_afternm_b([?P_BOXZEROBYTES, CipherText], Nonce, Key),
            bump(R, ?BOX_AFTERNM_REDUCTIONS, ?BOX_AFTERNM_SIZE, K);
        _ ->
            enacl_nif:crypto_box_open_afternm([?P_BOXZEROBYTES, CipherText], Nonce, Key)
    end.

%% @doc box_NONCEBYTES()/0 return the byte-size of the nonce
%%
%% Used to obtain the size of the nonce.
%% @end.
-spec box_NONCEBYTES() -> pos_integer().
box_NONCEBYTES() ->
    enacl_nif:crypto_box_NONCEBYTES().

%% @private
-spec box_PUBLICKEYBYTES() -> pos_integer().
box_PUBLICKEYBYTES() ->
    enacl_nif:crypto_box_PUBLICKEYBYTES().

%% @private
box_BEFORENMBYTES() ->
    enacl_nif:crypto_box_BEFORENMBYTES().

%% Signatures

%% @private
sign_PUBLICBYTES() ->
    enacl_nif:crypto_sign_PUBLICKEYBYTES().

%% @private
sign_SECRETBYTES() ->
    enacl_nif:crypto_sign_SECRETKEYBYTES().

%% @private
sign_SEEDBYTES() ->
    enacl_nif:crypto_sign_SEEDBYTES().

%% @doc sign_keypair/0 returns a signature keypair for signing
%%
%% The returned value is a map in order to make it harder to misuse keys.
%% @end
-spec sign_keypair() -> #{ atom() => binary() }.
sign_keypair() ->
    {PK, SK} = enacl_nif:crypto_sign_keypair(),
    #{ public => PK, secret => SK}.

%% @doc sign_seed_keypair/1 returns a signature keypair based on seed for signing
%%
%% The returned value is a map in order to make it harder to misuse keys.
%% @end
-spec sign_seed_keypair(S) -> #{ atom() => binary() }
    when
	  S :: binary().
sign_seed_keypair(S) ->
    {PK, SK} = enacl_nif:crypto_sign_seed_keypair(S),
    #{ public => PK, secret => SK}.

%% @doc sign/2 signs a message with a digital signature identified by a secret key.
%%
%% Given a message `M' and a secret key `SK' the function will sign the message and return a signed message `SM'.
%% @end
-spec sign(M, SK) -> SM
    when
      M :: iodata(),
      SK :: binary(),
      SM :: binary().
sign(M, SK) ->
    enacl_nif:crypto_sign(M, SK).

%% @doc sign_open/2 opens a digital signature
%%
%% Given a signed message `SM' and a public key `PK', verify that the message has the
%% right signature. Returns either `{ok, M}' or `{error, failed_verification}' depending
%% on the correctness of the signature.
%% @end
-spec sign_open(SM, PK) -> {ok, M} | {error, failed_verification}
    when
      SM :: iodata(),
      PK :: binary(),
      M :: binary().
sign_open(SM, PK) ->
    enacl_nif:crypto_sign_open(SM, PK).

%% @doc sign_detached/2 computes a digital signature given a message and a secret key.
%%
%% Given a message `M' and a secret key `SK' the function will compute the digital signature `DS'.
%% @end
-spec sign_detached(M, SK) -> DS
    when
      M  :: iodata(),
      SK :: binary(),
      DS :: binary().
sign_detached(M, SK) ->
    enacl_nif:crypto_sign_detached(M, SK).

%% @doc sign_verify_detached/3 verifies the given signature against the given
%% message for the given public key.
%%
%% Given a signature `SIG', a message `M', and a public key `PK', the function computes
%% true iff the `SIG' is valid for `M' and `PK'; false otherwise.
-spec sign_verify_detached(SIG, M, PK) -> boolean()
    when
      SIG :: binary(),
      M   :: iodata(),
      PK  :: binary().
sign_verify_detached(SIG, M, PK) ->
    enacl_nif:crypto_sign_verify_detached(SIG, M, PK).


%% @doc sign_init/0 initialize a multi-part signature state.
%%
%% This state must be passed to all future calls to `sign_update/2',
%% `sign_final_create/2' and `sign_final_verify/3'.
%% @end
-spec sign_init() -> sign_state().
sign_init() ->
    enacl_nif:crypto_sign_init().

%% @doc sign_update/2 update the signature state `S' with a new chunk of data `M'.
%% @end
-spec sign_update(S, M) -> sign_state() | {error, sign_update_error}
    when S :: sign_state(),
         M :: iodata().
sign_update(SignState, M) ->
    enacl_nif:crypto_sign_update(SignState, M).


%% @doc sign_final_create/2 computes the signature for the previously supplied
%% message(s) using the secret key `SK'.
%% @end
-spec sign_final_create(S, SK) -> {ok, binary()} | {error, atom()}
    when S :: sign_state(),
         SK :: iodata().
sign_final_create(SignState, SK) ->
    enacl_nif:crypto_sign_final_create(SignState, SK).

%% @doc sign_final_verify/3 verify a chunked signature
%%
%% Verifies that `SIG' is a valid signature for the message whose content has
%% been previously supplied using `sign_update/2' using the public key `PK.'
%% @end
-spec sign_final_verify(S, SIG, PK) -> boolean()
    when S :: sign_state(),
         SIG :: binary(),
         PK :: iodata().
sign_final_verify(SignState, SIG, PK) ->
    enacl_nif:crypto_sign_final_verify(SignState, SIG, PK).

%% @private
-spec box_SECRETKEYBYTES() -> pos_integer().
box_SECRETKEYBYTES() ->
    enacl_nif:crypto_box_SECRETKEYBYTES().

%% @doc seal_box/2 encrypts an anonymous message to another party.
%%
%% Encrypt a `Msg' to a party using his public key, `PK'. This generates an ephemeral
%% keypair and then uses `box'. Ephemeral public key will sent to other party. Returns the
%% enciphered message `SealedCipherText' which includes ephemeral public key at head.
%% @end
-spec box_seal(Msg, PK) -> SealedCipherText
    when
      Msg :: iodata(),
      PK :: binary(),
      SealedCipherText :: binary().
box_seal(Msg, PK) ->
    enacl_nif:crypto_box_seal(Msg, PK).

%% @doc seal_box_open/3 decrypts+check message integrity from an unknown sender.
%%
%% Decrypt a `SealedCipherText' which contains an ephemeral public key from another party
%% into a `Msg' using that key and your public and secret keys, `PK' and `SK'. Returns the
%% plaintext message.
%% @end
-spec box_seal_open(SealedCipherText, PK, SK) -> {ok, Msg} | {error, failed_verification}
    when
      SealedCipherText :: iodata(),
      PK :: binary(),
      SK :: binary(),
      Msg :: binary().
box_seal_open(SealedCipherText, PK, SK) ->
    enacl_nif:crypto_box_seal_open(SealedCipherText, PK, SK).

%% @doc secretbox/3 encrypts a message with a key
%%
%% Given a `Msg', a `Nonce' and a `Key' encrypt the message with the Key while taking the
%% nonce into consideration. The function returns the Box obtained from the encryption.
%% @end
-spec secretbox(Msg, Nonce, Key) -> Box
    when
      Msg :: iodata(),
      Nonce :: binary(),
      Key :: binary(),
      Box :: binary().
secretbox(Msg, Nonce, Key) ->
    case iolist_size(Msg) of
        K when K =< ?SECRETBOX_SIZE ->
            bump(enacl_nif:crypto_secretbox_b([?S_ZEROBYTES, Msg], Nonce, Key),
                 ?SECRETBOX_REDUCTIONS,
                 ?SECRETBOX_SIZE,
                 K);
        _ ->
            enacl_nif:crypto_secretbox([?S_ZEROBYTES, Msg], Nonce, Key)
    end.
%% @doc secretbox_open/3 opens a sealed box.
%%
%% Given a boxed `CipherText' and given we know the used `Nonce' and `Key' we can open the box
%% to obtain the `Msg` within. Returns either `{ok, Msg}' or `{error, failed_verification}'.
%% @end
-spec secretbox_open(CipherText, Nonce, Key) -> {ok, Msg} | {error, failed_verification}
    when
      CipherText :: iodata(),
      Nonce :: binary(),
      Key :: binary(),
      Msg :: binary().
secretbox_open(CipherText, Nonce, Key) ->
    case iolist_size(CipherText) of
        K when K =< ?SECRETBOX_SIZE ->
            R = enacl_nif:crypto_secretbox_open_b([?S_BOXZEROBYTES, CipherText],
                                                       Nonce, Key),
            bump(R, ?SECRETBOX_OPEN_REDUCTIONS, ?SECRETBOX_SIZE, K);
        _ ->
            enacl_nif:crypto_secretbox_open([?S_BOXZEROBYTES, CipherText], Nonce, Key)
    end.

%% @doc secretbox_NONCEBYTES()/0 returns the size of the secretbox nonce
%%
%% When encrypting with a secretbox, the nonce must have this size
%% @end
secretbox_NONCEBYTES() ->
    enacl_nif:crypto_secretbox_NONCEBYTES().

%% @doc secretbox_KEYBYTES/0 returns the size of the secretbox key
%%
%% When encrypting with a secretbox, the key must have this size
%% @end
secretbox_KEYBYTES() ->
    enacl_nif:crypto_secretbox_KEYBYTES().

%% @doc stream_chacha20_NONCEBYTES/0 returns the byte size of the nonce for streams
%% @end
-spec stream_chacha20_NONCEBYTES() -> ?CRYPTO_STREAM_CHACHA20_NONCEBYTES.
stream_chacha20_NONCEBYTES() ->
    ?CRYPTO_STREAM_CHACHA20_NONCEBYTES.

%% @doc stream_chacha20_KEYBYTES/0 returns the byte size of the key for streams
%% @end
-spec stream_chacha20_KEYBYTES() -> ?CRYPTO_STREAM_CHACHA20_KEYBYTES.
stream_chacha20_KEYBYTES() ->
    ?CRYPTO_STREAM_CHACHA20_KEYBYTES.

%% @doc stream_chacha20/3 produces a cryptographic stream suitable for secret-key encryption
%%
%% <p>Given a positive `Len' a `Nonce' and a `Key', the stream_chacha20/3 function will return an unpredictable cryptographic stream of bytes
%% based on this output. In other words, the produced stream is indistinguishable from a random stream. Using this stream one
%% can XOR it with a message in order to produce a encrypted message.</p>
%% <p><b>Note:</b>  You need to use different Nonce values for different messages. Otherwise the same stream is produced and thus
%% the messages will have predictability which in turn makes the encryption scheme fail.</p>
%% @end
-spec stream_chacha20(Len, Nonce, Key) -> CryptoStream
    when
      Len :: non_neg_integer(),
      Nonce :: binary(),
      Key :: binary(),
      CryptoStream :: binary().
stream_chacha20(Len, Nonce, Key) when is_integer(Len), Len >= 0, Len =< ?STREAM_SIZE ->
    bump(enacl_nif:crypto_stream_chacha20_b(Len, Nonce, Key),
         ?STREAM_REDUCTIONS,
         ?STREAM_SIZE,
         Len);
stream_chacha20(Len, Nonce, Key) when is_integer(Len), Len >= 0 ->
    enacl_nif:crypto_stream_chacha20(Len, Nonce, Key);
stream_chacha20(_, _, _) -> error(badarg).

%% @doc stream_chacha20_xor/3 encrypts a plaintext message into ciphertext
%%
%% The stream_chacha20_xor/3 function works by using the {@link stream_chacha20/3} api to XOR a message with the cryptographic stream. The same
%% caveat applies: the nonce must be new for each sent message or the system fails to work.
%% @end
-spec stream_chacha20_xor(Msg, Nonce, Key) -> CipherText
    when
      Msg :: iodata(),
      Nonce :: binary(),
      Key :: binary(),
      CipherText :: binary().
stream_chacha20_xor(Msg, Nonce, Key) ->
    case iolist_size(Msg) of
        K when K =< ?STREAM_SIZE ->
            bump(enacl_nif:crypto_stream_chacha20_xor_b(Msg, Nonce, Key),
                 ?STREAM_REDUCTIONS,
                 ?STREAM_SIZE,
                 K);
        _ ->
            enacl_nif:crypto_stream_chacha20_xor(Msg, Nonce, Key)
    end.

%% @doc stream_NONCEBYTES/0 returns the byte size of the nonce for streams
%% @end
-spec stream_NONCEBYTES() -> ?CRYPTO_STREAM_NONCEBYTES.
stream_NONCEBYTES() ->
    ?CRYPTO_STREAM_NONCEBYTES.

%% @doc stream_KEYBYTES/0 returns the byte size of the key for streams
%% @end
-spec stream_KEYBYTES() -> ?CRYPTO_STREAM_KEYBYTES.
stream_KEYBYTES() ->
    ?CRYPTO_STREAM_KEYBYTES.

%% @doc stream/3 produces a cryptographic stream suitable for secret-key encryption
%%
%% <p>Given a positive `Len' a `Nonce' and a `Key', the stream/3 function will return an unpredictable cryptographic stream of bytes
%% based on this output. In other words, the produced stream is indistinguishable from a random stream. Using this stream one
%% can XOR it with a message in order to produce a encrypted message.</p>
%% <p><b>Note:</b>  You need to use different Nonce values for different messages. Otherwise the same stream is produced and thus
%% the messages will have predictability which in turn makes the encryption scheme fail.</p>
%% @end
-spec stream(Len, Nonce, Key) -> CryptoStream
    when
      Len :: non_neg_integer(),
      Nonce :: binary(),
      Key :: binary(),
      CryptoStream :: binary().
stream(Len, Nonce, Key) when is_integer(Len), Len >= 0, Len =< ?STREAM_SIZE ->
    bump(enacl_nif:crypto_stream_b(Len, Nonce, Key),
         ?STREAM_REDUCTIONS,
         ?STREAM_SIZE,
         Len);
stream(Len, Nonce, Key) when is_integer(Len), Len >= 0 ->
    enacl_nif:crypto_stream(Len, Nonce, Key);
stream(_, _, _) -> error(badarg).

%% @doc stream_xor/3 encrypts a plaintext message into ciphertext
%%
%% The stream_xor/3 function works by using the {@link stream/3} api to XOR a message with the cryptographic stream. The same
%% caveat applies: the nonce must be new for each sent message or the system fails to work.
%% @end
-spec stream_xor(Msg, Nonce, Key) -> CipherText
    when
      Msg :: iodata(),
      Nonce :: binary(),
      Key :: binary(),
      CipherText :: binary().
stream_xor(Msg, Nonce, Key) ->
    case iolist_size(Msg) of
        K when K =< ?STREAM_SIZE ->
            bump(enacl_nif:crypto_stream_xor_b(Msg, Nonce, Key),
                 ?STREAM_REDUCTIONS,
                 ?STREAM_SIZE,
                 K);
        _ ->
            enacl_nif:crypto_stream_xor(Msg, Nonce, Key)
    end.

%% @doc auth_KEYBYTES/0 returns the byte-size of the authentication key
%% @end
-spec auth_KEYBYTES() -> pos_integer().
auth_KEYBYTES() ->
    enacl_nif:crypto_auth_KEYBYTES().

%% @doc auth_BYTES/0 returns the byte-size of the authenticator
%% @end
-spec auth_BYTES() -> pos_integer().
auth_BYTES() ->
    enacl_nif:crypto_auth_BYTES().

%% @doc auth/2 produces an authenticator (MAC) for a message
%%
%% Given a `Msg' and a `Key' produce a MAC/Authenticator for that message. The key can be reused for several such Msg/Authenticator pairs.
%% An eavesdropper will not learn anything extra about the message structure.
%% @end
-spec auth(Msg, Key) -> Authenticator
    when
      Msg :: iodata(),
      Key :: binary(),
      Authenticator :: binary().
auth(Msg, Key) ->
    case iolist_size(Msg) of
      K when K =< ?auth_BYTES ->
          bump(enacl_nif:crypto_auth_b(Msg, Key), ?AUTH_REDUCTIONS, ?auth_BYTES, K);
      _ ->
          enacl_nif:crypto_auth(Msg, Key)
  end.

%% @doc auth_verify/3 verifies an authenticator for a message
%%
%% Given an `Authenticator', a `Msg' and a `Key'; verify that the MAC for the pair `{Msg, Key}' is really `Authenticator'. Returns
%% the value `true' if the verfication passes. Upon failure, the function returns `false'.
%% @end
-spec auth_verify(Authenticator, Msg, Key) -> boolean()
    when
      Authenticator :: binary(),
      Msg :: iodata(),
      Key :: binary().
auth_verify(A, M, K) ->
    case iolist_size(M) of
        K when K =< ?auth_BYTES ->
            bump(enacl_nif:crypto_auth_verify_b(A, M, K),
                 ?AUTH_REDUCTIONS,
                 ?auth_BYTES,
                 K);
        _ ->
            enacl_nif:crypto_auth_verify(A, M, K)
    end.

%% @doc shorthash_key_size/0 returns the byte-size of the authentication key
%% @end
-spec shorthash_key_size() -> pos_integer().
shorthash_key_size() ->
    enacl_nif:crypto_shorthash_KEYBYTES().

%% @doc shorthash_size/0 returns the byte-size of the authenticator
%% @end
-spec shorthash_size() -> pos_integer().
shorthash_size() ->
    enacl_nif:crypto_shorthash_BYTES().

%% @doc shorthash/2 produces a short authenticator (MAC) for a message suitable for hashtables and refs
%%
%% Given a `Msg' and a `Key' produce a MAC/Authenticator for that message. The key can be reused for several such Msg/Authenticator pairs.
%% An eavesdropper will not learn anything extra about the message structure.
%%
%% The intended use is to generate a random key and use it as a hash table or bloom filter function.
%% This avoids an enemy their ability to predict where a collision would occur in the data structure,
%% since they don't know the key.
%% @end
-spec shorthash(Msg, Key) -> Authenticator
    when
      Msg :: iodata(),
      Key :: binary(),
      Authenticator :: binary().
shorthash(Msg, Key) ->
    enacl_nif:crypto_shorthash(Msg, Key).

%% @doc onetime_auth/2 produces a ONE-TIME authenticator for a message
%%
%% This function works like {@link auth/2} except that the key must not be used again for subsequent messages. That is, the pair
%% `{Msg, Key}' is unique and only to be used once. The advantage is noticably faster execution.
%% @end
-spec onetime_auth(Msg, Key) -> Authenticator
    when
      Msg :: iodata(),
      Key :: binary(),
      Authenticator :: binary().
onetime_auth(Msg, Key) ->
    case iolist_size(Msg) of
        K when K =< ?ONETIME_auth_BYTES ->
            bump(enacl_nif:crypto_onetimeauth_b(Msg, Key),
                 ?ONETIME_AUTH_REDUCTIONS,
                 ?ONETIME_auth_BYTES,
                 K);
        _ ->
            enacl_nif:crypto_onetimeauth(Msg, Key)
    end.

%% @doc onetime_auth_verify/3 verifies an ONE-TIME authenticator for a message
%%
%% Given an `Authenticator', a `Msg' and a `Key'; verify that the MAC for the pair `{Msg, Key}' is really `Authenticator'. Returns
%% the value `true' if the verification passes. Upon failure, the function returns `false'. Note the caveat from {@link onetime_auth/2}
%% applies: you are not allowed to ever use the same key again for another message.
%% @end
-spec onetime_auth_verify(Authenticator, Msg, Key) -> boolean()
    when
      Authenticator :: binary(),
      Msg :: iodata(),
      Key :: binary().
onetime_auth_verify(A, M, K) ->
    case iolist_size(M) of
        K when K =< ?ONETIME_auth_BYTES ->
            bump(enacl_nif:crypto_onetimeauth_verify_b(A, M, K),
                 ?ONETIME_AUTH_REDUCTIONS,
                 ?ONETIME_auth_BYTES,
                 K);
        _ ->
            enacl_nif:crypto_onetimeauth_verify(A, M, K)
    end.

%% @doc onetime_auth_BYTES/0 returns the number of bytes of the one-time authenticator
%% @end
-spec onetime_auth_BYTES() -> pos_integer().
onetime_auth_BYTES() ->
    enacl_nif:crypto_onetimeauth_BYTES().

%% @doc onetime_auth_KEYBYTES/0 returns the byte-size of the onetime authentication key
%% @end
-spec onetime_auth_KEYBYTES() -> pos_integer().
onetime_auth_KEYBYTES() ->
    enacl_nif:crypto_onetimeauth_KEYBYTES().

%% Curve 25519 Crypto
%% ------------------
%% @doc curve25519_scalarmult/2 does a scalar multiplication between the Secret and the BasePoint.
%% @end.
-spec curve25519_scalarmult(Secret :: binary(), BasePoint :: binary()) -> binary().
curve25519_scalarmult(Secret, BasePoint) ->
    enacl_nif:crypto_curve25519_scalarmult(Secret, BasePoint).

%% @doc curve25519_scalarmult/1 avoids messing up arguments.
%% Takes as input a map `#{ secret := Secret, base_point := BasePoint }' in order to avoid
%% messing up the calling order.
%% @end
curve25519_scalarmult(#{ secret := Secret, base_point := BasePoint }) ->
    curve25519_scalarmult(Secret, BasePoint).

%% @doc curve25519_scalarmult_base/1 compute the corresponding public key for a
%% given secret key.
%% @end.
-spec curve25519_scalarmult_base(Secret :: binary()) -> binary().
curve25519_scalarmult_base(Secret) ->
    enacl_nif:crypto_curve25519_scalarmult_base(Secret).

%% Ed 25519 Crypto
%% ---------------
%% @doc crypto_sign_ed25519_keypair/0 creates a new Ed 25519 Public/Secret keypair.
%%
%% Generates and returns a new key pair for the Ed 25519 signature scheme. The return value is a
%% map in order to avoid using the public key as a secret key and vice versa.
%% @end
-spec crypto_sign_ed25519_keypair() -> #{ atom() => binary() }.
crypto_sign_ed25519_keypair() ->
    {PK, SK} = enacl_nif:crypto_sign_ed25519_keypair(),
    #{ public => PK, secret => SK }.

%% @doc crypto_sign_ed25519_sk_to_pk/1 derives an ed25519 public key from a secret key
%% The ed25519 signatures secret keys contains enough information to dervice its corresponding
%% public key. This function extracts the public key from the secret if needed.
%% @end
-spec crypto_sign_ed25519_sk_to_pk(Secret :: binary()) -> binary().
crypto_sign_ed25519_sk_to_pk(Secret) ->
    enacl_nif:crypto_sign_ed25519_sk_to_pk(Secret).

%% @doc crypto_sign_ed25519_public_to_curve25519/1 converts a given Ed 25519 public
%% key to a Curve 25519 public key.
%% @end
-spec crypto_sign_ed25519_public_to_curve25519(PublicKey :: binary()) -> binary().
crypto_sign_ed25519_public_to_curve25519(PublicKey) ->
    R = enacl_nif:crypto_sign_ed25519_public_to_curve25519(PublicKey),
    erlang:bump_reductions(?ED25519_PUBLIC_TO_CURVE_REDS),
    R.

%% @doc crypto_sign_ed25519_secret_to_curve25519/1 converts a given Ed 25519 secret
%% key to a Curve 25519 secret key.
%% @end
-spec crypto_sign_ed25519_secret_to_curve25519(SecretKey :: binary()) -> binary().
crypto_sign_ed25519_secret_to_curve25519(SecretKey) ->
    R = enacl_nif:crypto_sign_ed25519_secret_to_curve25519(SecretKey),
    erlang:bump_reductions(?ED25519_SECRET_TO_CURVE_REDS),
    R.

-spec crypto_sign_ed25519_public_size() -> pos_integer().
crypto_sign_ed25519_public_size() ->
    enacl_nif:crypto_sign_ed25519_PUBLICKEYBYTES().

-spec crypto_sign_ed25519_secret_size() -> pos_integer().
crypto_sign_ed25519_secret_size() ->
    enacl_nif:crypto_sign_ed25519_SECRETKEYBYTES().

%% Key exchange functions
%% ----------------------
%% @doc kx_keypair/0 creates a new Public/Secret keypair.
%%
%% Generates and returns a new key pair for the key exchange. The return value is a
%% map in order to avoid using the public key as a secret key and vice versa.
%% @end
-spec kx_keypair() -> #{ atom() => binary() }.
kx_keypair() ->
    {PK, SK} = enacl_nif:crypto_kx_keypair(),
    #{ public => PK, secret => SK}.

%% @doc kx_client_session_keys/3 computes and returns shared keys for client session.
%%
%% <p>Compute two shared keys using the server's public key `ServerPk' and the client's secret key `ClientPk'.</p>
%% <p>Returns map with two keys `client_rx' and `client_tx'.
%% `client_rx' will be used by the client to receive data from the server,
%% `client_tx' will by used by the client to send data to the server.</p>
%% @end
-spec kx_client_session_keys(ClientPk, ClientSk, ServerPk) -> #{ atom() => binary() }
    when
      ClientPk :: binary(),
      ClientSk :: binary(),
      ServerPk :: binary().
kx_client_session_keys(ClientPk, ClientSk, ServerPk) ->
    {Rx, Tx} = enacl_nif:crypto_kx_client_session_keys(ClientPk, ClientSk, ServerPk),
    #{ client_rx => Rx, client_tx => Tx}.

%% @doc kx_server_session_keys/3 computes and returns shared keys for server session.
%% <p>Compute two shared keys using the client's public key `ClientPk'  and the server's secret key `ServerSk'.</p>
%% <p>Returns map with two keys `server_rx' and `server_tx'.
%% `server_rx' will be used by the server to receive data from the client,
%% `server_tx' will be used by the server to send data to the client.</p>
%% @end
-spec kx_server_session_keys(ServerPk, ServerSk, ClientPk) -> #{ atom() => binary() }
    when
      ServerPk :: binary(),
      ServerSk :: binary(),
      ClientPk :: binary().
kx_server_session_keys(ServerPk, ServerSk, ClientPk) ->
    {Rx, Tx} = enacl_nif:crypto_kx_server_session_keys(ServerPk, ServerSk, ClientPk),
    #{ server_rx => Rx, server_tx => Tx}.

%% @doc kx_SESSIONKEYBYTES/0 returns the number of bytes of the generated during key exchange session key.
%% @end
-spec kx_SESSIONKEYBYTES() -> pos_integer().
kx_SESSIONKEYBYTES() ->
    enacl_nif:crypto_kx_SESSIONKEYBYTES().

%% @doc kx_PUBLICKEYBYTES/0 returns the number of bytes of the public key used in key exchange.
%% @end
-spec kx_PUBLICKEYBYTES() -> pos_integer().
kx_PUBLICKEYBYTES() ->
    enacl_nif:crypto_kx_PUBLICKEYBYTES().

%% @doc kx_SECRETKEYBYTES/0 returns the number of bytes of the secret key used in key exchange.
%% @end
-spec kx_SECRETKEYBYTES() -> pos_integer().
kx_SECRETKEYBYTES() ->
    enacl_nif:crypto_kx_SECRETKEYBYTES().

%% AEAD ChaCha20 Poly1305
%% ----------------------
%% @doc aead_chacha20poly1305_encrypt/4 encrypts `Message' with additional data
%% `AD' using `Key' and `Nonce'. Returns the encrypted message followed by
%% aead_chacha20poly1305_ABYTES/0 bytes of MAC.
%% @end
-spec aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key) -> binary()
    when Key :: binary(),
         Nonce :: binary(),
         AD :: binary(),
         Msg :: binary().
aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key) ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key).

%% @doc aead_chacha20poly1305_decrypt/4 decrypts ciphertext `CT' with additional
%% data `AD' using `Key' and `Nonce'. Note: `CipherText' should contain
%% aead_chacha20poly1305_ABYTES/0 bytes that is the MAC. Returns the decrypted
%% message.
%% @end
-spec aead_chacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) -> binary() | {error, term()}
    when Key :: binary(),
         Nonce :: binary(),
         AD :: binary(),
         CT :: binary().
aead_chacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key).

%% @doc aead_chacha20poly1305_KEYBYTES/0 returns the number of bytes
%% of the key used in AEAD ChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_chacha20poly1305_ietf_KEYBYTES() -> pos_integer().
aead_chacha20poly1305_ietf_KEYBYTES() ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_KEYBYTES().

%% @doc aead_chacha20poly1305_NPUBBYTES/0 returns the number of bytes
%% of the Nonce in AEAD ChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_chacha20poly1305_ietf_NPUBBYTES() -> pos_integer().
aead_chacha20poly1305_ietf_NPUBBYTES() ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_NPUBBYTES().

%% @doc aead_chacha20poly1305_ABYTES/0 returns the number of bytes
%% of the MAC in AEAD ChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_chacha20poly1305_ietf_ABYTES() -> pos_integer().
aead_chacha20poly1305_ietf_ABYTES() ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_ABYTES().

%% @doc aead_chacha20poly1305_MESSAGEBYTES_MAX/0 returns the max number of bytes
%% allowed in a message in AEAD ChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX() -> pos_integer().
aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX() ->
    enacl_nif:crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX().

%% AEAD XChaCha20 Poly1305
%% ----------------------
%% @doc aead_xchacha20poly1305_encrypt/4 encrypts `Message' with additional data
%% `AD' using `Key' and `Nonce'. Returns the encrypted message followed by
%% `aead_xchacha20poly1305_ABYTES/0' bytes of MAC.
%% @end
-spec aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key) -> binary()
    when Key :: binary(),
         Nonce :: binary(),
         AD :: binary(),
         Msg :: binary().
aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key) ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key).

%% @doc aead_xchacha20poly1305_decrypt/4 decrypts ciphertext `CT' with additional
%% data `AD' using `Key' and `Nonce'. Note: `CipherText' should contain
%% `aead_xchacha20poly1305_ABYTES/0' bytes that is the MAC. Returns the decrypted
%% message.
%% @end
-spec aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) -> binary() | {error, term()}
    when Key :: binary(),
         Nonce :: binary(),
         AD :: binary(),
         CT :: binary().
aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key).

%% @doc aead_xchacha20poly1305_KEYBYTES/0 returns the number of bytes
%% of the key used in AEAD XChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_xchacha20poly1305_ietf_KEYBYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_KEYBYTES() ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_KEYBYTES().

%% @doc aead_xchacha20poly1305_NPUBBYTES/0 returns the number of bytes
%% of the Nonce in AEAD XChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_xchacha20poly1305_ietf_NPUBBYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_NPUBBYTES() ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_NPUBBYTES().

%% @doc aead_xchacha20poly1305_ABYTES/0 returns the number of bytes
%% of the MAC in AEAD XChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_xchacha20poly1305_ietf_ABYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_ABYTES() ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_ABYTES().

%% @doc aead_xchacha20poly1305_MESSAGEBYTES_MAX/0 returns the max number of bytes
%% allowed in a message in AEAD XChaCha20 Poly1305 encryption/decryption.
%% @end
-spec aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX() -> pos_integer().
aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX() ->
    enacl_nif:crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX().

%% Secretstream
%% ----------------------
%% @doc secretstream_xchacha20poly1305_ABYTES/0 returns the number of bytes
%% of the MAC used on secretstream encryption/decryption
%% @end
-spec secretstream_xchacha20poly1305_ABYTES() -> pos_integer().
secretstream_xchacha20poly1305_ABYTES() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_ABYTES().

%% @doc secretstream_xchacha20poly1305_HEADERBYTES/0 returns the number
%% of bytes for header used in secretstream encryption/decryption.
%% @end
-spec secretstream_xchacha20poly1305_HEADERBYTES() -> pos_integer().
secretstream_xchacha20poly1305_HEADERBYTES() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_HEADERBYTES().

%% @doc secretstream_xchacha20poly1305_KEYBYTES/0 returns the number
%% of bytes of the key used in secretstream encryption/decryption.
%% @end
-spec secretstream_xchacha20poly1305_KEYBYTES() -> pos_integer().
secretstream_xchacha20poly1305_KEYBYTES() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_KEYBYTES().

%% @doc secretstream_xchacha20poly1305_MESSAGEBYTES_MAX/0 returns the max
%% number of bytes allowed in a message in secretstream encryption/decryption.
%% @end
-spec secretstream_xchacha20poly1305_MESSAGEBYTES_MAX() -> pos_integer().
secretstream_xchacha20poly1305_MESSAGEBYTES_MAX() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX().

%% @doc secretstream_xchacha20poly1305_TAG_MESSAGE/0 returns integer value
%% of tag `message'. The most common tag, that doesn't add any information
%% about the nature of the message.
%% @end
-spec secretstream_xchacha20poly1305_TAG_MESSAGE() -> pos_integer().
secretstream_xchacha20poly1305_TAG_MESSAGE() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_MESSAGE().

%% @doc secretstream_xchacha20poly1305_TAG_PUSH/0 returns integer value
%% of tag `push'.
%%
%% This tag indicates that the message marks the end
%% of a set of messages, but not the end of the stream.
%%
%% For example, a huge JSON string sent as multiple chunks can use
%% this tag to indicate to the application that the string is complete
%% and that it can be decoded. But the stream itself is not closed,
%% and more data may follow.
%% @end
-spec secretstream_xchacha20poly1305_TAG_PUSH() -> pos_integer().
secretstream_xchacha20poly1305_TAG_PUSH() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_PUSH().

%% @doc secretstream_xchacha20poly1305_TAG_REKEY/0 returns integer value
%% of tag `rekey'. Indicates that next messages will derive new keys.
%% @end
-spec secretstream_xchacha20poly1305_TAG_REKEY() -> pos_integer().
secretstream_xchacha20poly1305_TAG_REKEY() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_REKEY().

%% @doc secretstream_xchacha20poly1305_TAG_FINAL/0 returns integer value
%% of tag `final'. Indicates that the message is the last message in
%% the secretstream.
%% @end
-spec secretstream_xchacha20poly1305_TAG_FINAL() -> pos_integer().
secretstream_xchacha20poly1305_TAG_FINAL() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_FINAL().

%% @doc secretstream_xchacha20poly1305_keygen/0 returns new random key
%% for secretsteam encryption.
%% @end
-spec secretstream_xchacha20poly1305_keygen() -> binary().
secretstream_xchacha20poly1305_keygen() ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_keygen().

%% @doc secretstream_xchacha20poly1305_init_push/1
%% initializes a secretstream encryption context using given `key'.
%% Returns `Header' and reference to encryption context.
%% @end
-spec secretstream_xchacha20poly1305_init_push(Key) -> {binary(), reference()}
    when Key :: binary().
secretstream_xchacha20poly1305_init_push(Key) ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_init_push(Key).

%% @doc secretstream_xchacha20poly1305_push/4 returns encrypted chunk binary.
%% Updates a secretstream context referenced by `Ref' with `Message' data,
%% given `Tag' and additional data `AD'.
%% @end
-spec secretstream_xchacha20poly1305_push(Ref, Message, AD, Tag) -> binary()
    when
      Ref     :: reference(),
      Message :: binary(),
      AD      :: binary(),
      Tag     :: secretstream_xchacha20poly1305_tag().
secretstream_xchacha20poly1305_push(Ref, Message, AD, Tag) ->
    TagValue = secretstream_xchacha20poly1305_tag_value(Tag),

    enacl_nif:crypto_secretstream_xchacha20poly1305_push(Ref, Message, AD, TagValue).

%% @doc secretstream_xchacha20poly1305_init_pull/3
%% initializes a secretstream decryption context using `Header' and `Key'.
%% Returns reference to decryption context.
%% @end
-spec secretstream_xchacha20poly1305_init_pull(Header, Key) -> reference()
    when
      Header :: binary(),
      Key    :: binary().
secretstream_xchacha20poly1305_init_pull(Header, Key) ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_init_pull(Header, Key).

%% @doc secretstream_xchacha20poly1305_pull/3 decrypts `CipherText'
%% with additional data `AD' in referenced decryption context `Ref'.
%% @end
-spec secretstream_xchacha20poly1305_pull(Ref, CipherText, AD) ->
  {binary(), secretstream_xchacha20poly1305_tag()} | {error, failed_verification}
    when
      Ref        :: reference(),
      CipherText :: binary(),
      AD         :: binary().
secretstream_xchacha20poly1305_pull(Ref, CipherText, AD) ->
    {Message, TagValue} = enacl_nif:crypto_secretstream_xchacha20poly1305_pull(Ref, CipherText, AD),
    {Message, secretstream_xchacha20poly1305_tag(TagValue)}.

%% @doc secretstream_xchacha20poly1305_rekey/1 updates encryption/decryption context state.
%% This doesn't add any information about key update to stream.
%% If this function is used to create an encrypted stream,
%% the decryption process must call that function at the exact same stream location.
%% @end
-spec secretstream_xchacha20poly1305_rekey(Ref) -> ok
    when Ref :: reference().
secretstream_xchacha20poly1305_rekey(Ref) ->
    enacl_nif:crypto_secretstream_xchacha20poly1305_rekey(Ref).

%% @doc secretstream_xchacha20poly1305_tag_value/1 returns integer value of tag.
%% @end
-spec secretstream_xchacha20poly1305_tag_value(TagName) -> pos_integer()
    when TagName :: secretstream_xchacha20poly1305_tag().
secretstream_xchacha20poly1305_tag_value(message) ->
  enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_MESSAGE();
secretstream_xchacha20poly1305_tag_value(rekey) ->
  enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_REKEY();
secretstream_xchacha20poly1305_tag_value(push) ->
  enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_PUSH();
secretstream_xchacha20poly1305_tag_value(final) ->
  enacl_nif:crypto_secretstream_xchacha20poly1305_TAG_FINAL();
secretstream_xchacha20poly1305_tag_value(Other) ->
  Other.

%% @doc secretstream_xchacha20poly1305_tag/1 returns tag name
%% @end
-spec secretstream_xchacha20poly1305_tag(TagValue) -> secretstream_xchacha20poly1305_tag()
    when TagValue :: pos_integer().
secretstream_xchacha20poly1305_tag(?CRYPTO_SECRETSTREAM_TAG_MESSAGE) ->
  message;
secretstream_xchacha20poly1305_tag(?CRYPTO_SECRETSTREAM_TAG_PUSH) ->
  push;
secretstream_xchacha20poly1305_tag(?CRYPTO_SECRETSTREAM_TAG_REKEY) ->
  rekey;
secretstream_xchacha20poly1305_tag(?CRYPTO_SECRETSTREAM_TAG_FINAL) ->
  final;
secretstream_xchacha20poly1305_tag(Other) ->
  Other.

%% Obtaining random bytes
%% ----------------------

%% @doc randombytes/1 produces a stream of random bytes of the given size
%%
%% The security properties of the random stream are that of the libsodium library. Specifically,
%% we use:
%%
%% * RtlGenRandom() on Windows systems
%% * arc4random() on OpenBSD and Bitrig
%% * /dev/urandom on other Unix environments
%%
%% It is up to you to pick a system with a appropriately strong (P)RNG for your purpose. We refer
%% you to the underlying system implementations for random data.
%% @end
-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) ->
    enacl_nif:randombytes(N).

%% @doc randombytes_uint32/0 produces an integer in the 32bit range
%% @end
-spec randombytes_uint32() -> integer().
randombytes_uint32() ->
    enacl_nif:randombytes_uint32().

%% @doc randombytes_uniform/1 produces a random integer in the space [0..N)
%% That is with the upper bound excluded. Fails for integers above 32bit size
%% @end
randombytes_uniform(N) when N < ?MAX_32BIT_INT ->
    enacl_nif:randombytes_uniform(N).

%% Helpers

%% @doc bump/4 bumps a reduction budget linearly before returning the result
%% It is used for the on-scheduler variants of functions in order to make sure there
%% is a realistic apporach to handling the reduction counts of the system.
%% @end
bump(Res, Budget, Max, Sz) ->
    Reds =  (Budget * Sz) div Max,
    erlang:bump_reductions(max(1, Reds)),
    Res.
