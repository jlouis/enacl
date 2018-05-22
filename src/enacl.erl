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
%%% <p><b>Warning:</b> The cryptographic strength of your implementation is no stronger than
%%% plaintext cryptography unless you take care in using these primitives correctly. Hence,
%%% implementors should use these primitives with that in mind.</p>
%%% <p><b>Note:</b> All functions will fail with a `badarg' error if given incorrect
%%% parameters.</p>
%%% @end.
-module(enacl).

%% Public key crypto
-export([
         box_keypair/0,
         box/4,
         box_open/4,
         box_beforenm/2,
         box_afternm/3,
         box_open_afternm/3,

         box_nonce_size/0,
         box_public_key_bytes/0,
         box_secret_key_bytes/0,
         box_beforenm_bytes/0,

         sign_keypair_public_size/0,
         sign_keypair_secret_size/0,
         sign_keypair/0,
         sign/2,
         sign_open/2,
         sign_detached/2,
         sign_verify_detached/3,

         box_seal/2,
         box_seal_open/3
]).

%% Secret key crypto
-export([
         secretbox_key_size/0,
         secretbox_nonce_size/0,
         secretbox/3,
         secretbox_open/3,

         stream_chacha20_key_size/0,
         stream_chacha20_nonce_size/0,
         stream_chacha20/3,
         stream_chacha20_xor/3,

         stream_key_size/0,
         stream_nonce_size/0,
         stream/3,
         stream_xor/3,

         auth_key_size/0,
         auth_size/0,
         auth/2,
         auth_verify/3,

         shorthash_key_size/0,
         shorthash_size/0,
         shorthash/2,

         onetime_auth_key_size/0,
         onetime_auth_size/0,
         onetime_auth/2,
         onetime_auth_verify/3
]).

%% Curve 25519.
-export([
         curve25519_scalarmult/1, curve25519_scalarmult/2
]).

%% Ed 25519.
-export([
         crypto_sign_ed25519_keypair/0,
         crypto_sign_ed25519_public_to_curve25519/1,
         crypto_sign_ed25519_secret_to_curve25519/1,
         crypto_sign_ed25519_public_size/0,
         crypto_sign_ed25519_secret_size/0
        ]).

%% Low-level functions
-export([
         hash/1,
         verify_16/2,
         verify_32/2,
         unsafe_memzero/1
]).

%% Key exchange functions
-export([
         kx_keypair/0,
         kx_client_session_keys/3,
         kx_server_session_keys/3,
         kx_public_key_size/0,
         kx_secret_key_size/0,
         kx_session_key_size/0
]).

%% Password Hashing - Argon2 Algorithm
-export([
         pwhash/2,
         pwhash_str/1,
         pwhash_str_verify/2
]).

%% Generic hash functions
-export([
         generichash/3,
         generichash/2,
         generichash_init/2,
         generichash_update/2,
         generichash_final/1
]).

%% Libsodium specific functions (which are also part of the "undocumented" interface to NaCl
-export([
         randombytes/1,
	 randomint/0,
	 randomint/1,
	 randomint/2
]).

-export([
         verify/0
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
-define(AUTH_SIZE, 4 * 1024).
-define(AUTH_REDUCTIONS, 17 * 2).
-define(ONETIME_AUTH_SIZE, 16 * 1024).
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
         {crypto_generichash_KEYBYTES_MAX, ?CRYPTO_GENERICHASH_KEYBYTES_MAX}
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
-type generichash_bytes() :: ?CRYPTO_GENERICHASH_BYTES_MIN..?CRYPTO_GENERICHASH_BYTES_MAX.
-spec generichash(generichash_bytes(), iodata(), binary()) -> {ok, binary()} | {error, term()}.
generichash(HashSize, Message, Key) ->
    enacl_nif:crypto_generichash(HashSize, Message, Key).

%% @doc generichash/2 creates a hash of the message.
%%
%% This function generates a hash of the message. The hash size is
%% either 16, 32 or 64 bytes
%% @end
-spec generichash(generichash_bytes(), iodata()) -> {ok, binary()} | {error, term()}.
generichash(HashSize, Message) ->
    enacl_nif:crypto_generichash(HashSize, Message, <<>>).

generichash_init(HashSize, Key) ->
    enacl_nif:crypto_generichash_init(HashSize, Key).

generichash_update({hashstate, HashSize, HashState}, Message) ->
    enacl_nif:crypto_generichash_update(HashSize, HashState, Message).

generichash_final({hashstate, HashSize, HashState}) ->
    enacl_nif:crypto_generichash_final(HashSize, HashState).


%% @doc pwhash/2 hash a password
%%
%% This function generates a fixed size salted hash of a user defined password.
%% @end
-spec pwhash(iodata(), binary()) -> {ok, binary()} | {error, term()}.
pwhash(Password, Salt) ->
    enacl_nif:crypto_pwhash(Password, Salt).

%% @doc pwhash_str/1 generates a ASCII encoded hash of a password
%%
%% This function generates a fixed size, salted, ASCII encoded hash of a user defined password.
%% @end
-spec pwhash_str(iodata()) -> {ok, iodata()} | {error, term()}.
pwhash_str(Password) ->
    enacl_nif:crypto_pwhash_str(Password).

%% @doc pwhash_str_verify/2 compares a password with a hash
%%
%% This function verifies that the hash is generated from the password. The
%% function returns true if the verifcate succeeds, false otherwise
%% @end
-spec pwhash_str_verify(binary(), iodata()) -> boolean().
pwhash_str_verify(HashPassword, Password) ->
    enacl_nif:crypto_pwhash_str_verify(HashPassword, Password).

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
    case enacl_nif:crypto_box_open([?P_BOXZEROBYTES, CipherText], Nonce, PK, SK) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

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
            R =
                case enacl_nif:crypto_box_open_afternm_b(
                       [?P_BOXZEROBYTES, CipherText], Nonce, Key) of
                    {error, Err} ->
                        {error, Err};
                    Bin when is_binary(Bin) ->
                        {ok, Bin}
                end,
            bump(R, ?BOX_AFTERNM_REDUCTIONS, ?BOX_AFTERNM_SIZE, K);
        _ ->
            case enacl_nif:crypto_box_open_afternm(
                   [?P_BOXZEROBYTES, CipherText], Nonce, Key) of
                {error, Err} ->
                    {error, Err};
                Bin when is_binary(Bin) ->
                    {ok, Bin}
            end
    end.

%% @doc box_nonce_size/0 return the byte-size of the nonce
%%
%% Used to obtain the size of the nonce.
%% @end.
-spec box_nonce_size() -> pos_integer().
box_nonce_size() ->
    enacl_nif:crypto_box_NONCEBYTES().

%% @private
-spec box_public_key_bytes() -> pos_integer().
box_public_key_bytes() ->
    enacl_nif:crypto_box_PUBLICKEYBYTES().

%% @private
box_beforenm_bytes() ->
    enacl_nif:crypto_box_BEFORENMBYTES().

%% Signatures

%% @private
sign_keypair_public_size() ->
    enacl_nif:crypto_sign_PUBLICKEYBYTES().

%% @private
sign_keypair_secret_size() ->
    enacl_nif:crypto_sign_SECRETKEYBYTES().

%% @doc sign_keypair/0 returns a signature keypair for signing
%%
%% The returned value is a map in order to make it harder to misuse keys.
%% @end
-spec sign_keypair() -> #{ atom() => binary() }.
sign_keypair() ->
    {PK, SK} = enacl_nif:crypto_sign_keypair(),
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
    case enacl_nif:crypto_sign_open(SM, PK) of
        M when is_binary(M) -> {ok, M};
        {error, Err} -> {error, Err}
    end.

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
%% true iff the `SIG' is valid for `M' and `PK'.
-spec sign_verify_detached(SIG, M, PK) -> {ok, M} | {error, failed_verification}
    when
      SIG :: binary(),
      M   :: iodata(),
      PK  :: binary().
sign_verify_detached(SIG, M, PK) ->
    case enacl_nif:crypto_sign_verify_detached(SIG, M, PK) of
        true -> {ok, M};
        false -> {error, failed_verification}
    end.

%% @private
-spec box_secret_key_bytes() -> pos_integer().
box_secret_key_bytes() ->
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
    case enacl_nif:crypto_box_seal_open(SealedCipherText, PK, SK) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

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
            R = case enacl_nif:crypto_secretbox_open_b([?S_BOXZEROBYTES, CipherText],
                                                       Nonce, Key) of
                    {error, Err} -> {error, Err};
                    Bin when is_binary(Bin) -> {ok, Bin}
                end,
            bump(R, ?SECRETBOX_OPEN_REDUCTIONS, ?SECRETBOX_SIZE, K);
        _ ->
            case enacl_nif:crypto_secretbox_open([?S_BOXZEROBYTES, CipherText], Nonce, Key) of
                {error, Err} -> {error, Err};
                Bin when is_binary(Bin) -> {ok, Bin}
            end
    end.

%% @doc secretbox_nonce_size/0 returns the size of the secretbox nonce
%%
%% When encrypting with a secretbox, the nonce must have this size
%% @end
secretbox_nonce_size() ->
    enacl_nif:crypto_secretbox_NONCEBYTES().

%% @doc secretbox_key_size/0 returns the size of the secretbox key
%%
%% When encrypting with a secretbox, the key must have this size
%% @end
secretbox_key_size() ->
    enacl_nif:crypto_secretbox_KEYBYTES().

%% @doc stream_chacha20_nonce_size/0 returns the byte size of the nonce for streams
%% @end
-spec stream_chacha20_nonce_size() -> ?CRYPTO_STREAM_CHACHA20_NONCEBYTES.
stream_chacha20_nonce_size() ->
    ?CRYPTO_STREAM_CHACHA20_NONCEBYTES.

%% @doc stream_key_size/0 returns the byte size of the key for streams
%% @end
-spec stream_chacha20_key_size() -> ?CRYPTO_STREAM_CHACHA20_KEYBYTES.
stream_chacha20_key_size() ->
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

%% @doc stream_nonce_size/0 returns the byte size of the nonce for streams
%% @end
-spec stream_nonce_size() -> ?CRYPTO_STREAM_NONCEBYTES.
stream_nonce_size() ->
    ?CRYPTO_STREAM_NONCEBYTES.

%% @doc stream_key_size/0 returns the byte size of the key for streams
%% @end
-spec stream_key_size() -> ?CRYPTO_STREAM_KEYBYTES.
stream_key_size() ->
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

%% @doc auth_key_size/0 returns the byte-size of the authentication key
%% @end
-spec auth_key_size() -> pos_integer().
auth_key_size() ->
    enacl_nif:crypto_auth_KEYBYTES().

%% @doc auth_size/0 returns the byte-size of the authenticator
%% @end
-spec auth_size() -> pos_integer().
auth_size() ->
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
      K when K =< ?AUTH_SIZE ->
          bump(enacl_nif:crypto_auth_b(Msg, Key), ?AUTH_REDUCTIONS, ?AUTH_SIZE, K);
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
        K when K =< ?AUTH_SIZE ->
            bump(enacl_nif:crypto_auth_verify_b(A, M, K),
                 ?AUTH_REDUCTIONS,
                 ?AUTH_SIZE,
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
        K when K =< ?ONETIME_AUTH_SIZE ->
            bump(enacl_nif:crypto_onetimeauth_b(Msg, Key),
                 ?ONETIME_AUTH_REDUCTIONS,
                 ?ONETIME_AUTH_SIZE,
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
        K when K =< ?ONETIME_AUTH_SIZE ->
            bump(enacl_nif:crypto_onetimeauth_verify_b(A, M, K),
                 ?ONETIME_AUTH_REDUCTIONS,
                 ?ONETIME_AUTH_SIZE,
                 K);
        _ ->
            enacl_nif:crypto_onetimeauth_verify(A, M, K)
    end.

%% @doc onetime_auth_size/0 returns the number of bytes of the one-time authenticator
%% @end
-spec onetime_auth_size() -> pos_integer().
onetime_auth_size() ->
    enacl_nif:crypto_onetimeauth_BYTES().

%% @doc onetime_auth_key_size/0 returns the byte-size of the onetime authentication key
%% @end
-spec onetime_auth_key_size() -> pos_integer().
onetime_auth_key_size() ->
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

%% @doc kx_session_key_size/0 returns the number of bytes of the generated during key exchange session key.
%% @end
-spec kx_session_key_size() -> pos_integer().
kx_session_key_size() ->
    enacl_nif:crypto_kx_SESSIONKEYBYTES().

%% @doc kx_public_key_size/0 returns the number of bytes of the public key used in key exchange.
%% @end
-spec kx_public_key_size() -> pos_integer().
kx_public_key_size() ->
    enacl_nif:crypto_kx_PUBLICKEYBYTES().

%% @doc kx_secret_key_size/0 returns the number of bytes of the secret key used in key exchange.
%% @end
-spec kx_secret_key_size() -> pos_integer().
kx_secret_key_size() ->
    enacl_nif:crypto_kx_SECRETKEYBYTES().



%% Obtaining random bytes

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


%% @doc randomint/0 returns an unpredictable value between 0 and 0xffffffff (included).
%% @end
-spec randomint() -> non_neg_integer().
randomint() ->
    enacl_nif:randomint().

%% @doc randomint/1 function returns an unpredictable value between 0 and given upper bound (excluded)
%%
%% It guarantees a uniform distribution of the possible 
%% output values even when upper bound is not a power of 2.
%% @end
-spec randomint(non_neg_integer()) -> non_neg_integer().
randomint(UpperBound) ->
    enacl_nif:randomint(UpperBound).

%% @doc randomint/2 function returns an unpredictable value between 1 and given upper bound (included)
%%
%% It guarantees a uniform distribution of the possible 
%% output values even when upper bound is not a power of 2.
%% @end
-spec randomint(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
randomint(LowerBound, UpperBound) ->
    enacl_nif:randomint(LowerBound, UpperBound).

%% Helpers

%% @doc bump/4 bumps a reduction budget linearly before returning the result
%% It is used for the on-scheduler variants of functions in order to make sure there
%% is a realistic apporach to handling the reduction counts of the system.
%% @end
bump(Res, Budget, Max, Sz) ->
    Reds =  (Budget * Sz) div Max,
    erlang:bump_reductions(max(1, Reds)),
    Res.
