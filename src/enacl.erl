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

	seal_box/2,
	seal_box_open/3
]).

%% Secret key crypto
-export([
	secretbox_key_size/0,
	secretbox_nonce_size/0,
	secretbox/3,
	secretbox_open/3,

	stream_key_size/0,
	stream_nonce_size/0,
	stream/3,
	stream_xor/3,

	auth_key_size/0,
	auth_size/0,
	auth/2,
	auth_verify/3,

	onetime_auth_key_size/0,
	onetime_auth_size/0,
	onetime_auth/2,
	onetime_auth_verify/3
]).

%% Curve 25519.
-export([
	curve25519_scalarmult/2
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
	verify_32/2
]).

%% Libsodium specific functions (which are also part of the "undocumented" interface to NaCl
-export([
	randombytes/1
]).

%% Other helper functions
-export([
	reds/1
]).

%% Definitions of system budgets
%% To get a grip for these, call `enacl_timing:all/0' on your system. The numbers here are
%% described in the README.md file.
-define(HASH_SIZE, 32 * 1024).
-define(HASH_REDUCTIONS, 104 * 2).
-define(BOX_SIZE, 32 * 1024).
-define(BOX_REDUCTIONS, 115 * 2).
-define(BOX_BEFORENM_REDUCTIONS, 60).
-define(BOX_AFTERNM_SIZE, 64 * 1024).
-define(BOX_AFTERNM_REDUCTIONS, 110 * 2).
-define(SIGN_SIZE, 16 * 1024).
-define(SIGN_REDUCTIONS, 160 * 2).
-define(SECRETBOX_SIZE, 64 * 1024).
-define(SECRETBOX_REDUCTIONS, 107 * 2).
-define(SECRETBOX_OPEN_REDUCTIONS, 51 * 2).
-define(STREAM_SIZE, 128 * 1024).
-define(STREAM_REDUCTIONS, 120 * 2).
-define(AUTH_SIZE, 32 * 1024).
-define(AUTH_REDUCTIONS, 102 * 2).
-define(ONETIME_AUTH_SIZE, 128 * 1024).
-define(ONETIME_AUTH_REDUCTIONS, 105 * 2).
-define(RANDOMBYTES_SIZE, 1024).
-define(RANDOMBYTES_REDUCTIONS, 200).

%% @doc reds/1 counts the number of reductions and scheduler yields for a thunk
%%
%% Count reductions and number of scheduler yields for Fun. Fun is assumed
%% to be one of the above exor variants.
%% @end
-spec reds(fun (() -> any())) -> #{ atom() => any() }.
reds(Fun) ->
    Parent = self(),
    Pid = spawn(fun() ->
                        Self = self(),
                        Start = os:timestamp(),
                        R0 = process_info(Self, reductions),
                        Fun(),
                        R1 = process_info(Self, reductions),
                        T = timer:now_diff(os:timestamp(), Start),
                        Parent ! {Self,#{ time_diff => T, after_reductions => R1, before_reductions => R0}}
                    end),
    receive
        {Pid,Result} ->
            Result
    end.

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
  when Data :: iodata(),
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
verify_16(X, Y) when is_binary(X), is_binary(Y) -> enacl_nif:crypto_verify_16(X, Y);
verify_16(_, _) -> error(badarg).

%% @doc verify_32/2 implements constant time 32-byte iolist() verification
%%
%% This function works as {@link verify_16/2} but does so on 32 byte strings. Same caveats apply.
%% @end
-spec verify_32(binary(), binary()) -> boolean().
verify_32(X, Y) when is_binary(X), is_binary(Y) -> enacl_nif:crypto_verify_32(X, Y);
verify_32(_, _) -> error(badarg).

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
  when Msg :: iodata(),
       Nonce :: binary(),
       PK :: binary(),
       SK :: binary(),
       CipherText :: binary().
box(Msg, Nonce, PK, SK) ->
    case iolist_size(Msg) of
        K when K =< ?BOX_SIZE ->
            bump(enacl_nif:crypto_box_b([p_zerobytes(), Msg], Nonce, PK, SK), ?BOX_REDUCTIONS, ?BOX_SIZE, K);
        _ ->
            enacl_nif:crypto_box([p_zerobytes(), Msg], Nonce, PK, SK)
    end.

%% @doc box_open/4 decrypts+verifies a message from another party.
%%
%% Decrypt a `CipherText' into a `Msg' given the other partys public key `PK' and your secret
%% key `SK'. Also requires the same nonce as was used by the other party. Returns the plaintext
%% message.
%% @end
-spec box_open(CipherText, Nonce, PK, SK) -> {ok, Msg} | {error, failed_verification}
  when CipherText :: iodata(),
       Nonce :: binary(),
       PK :: binary(),
       SK :: binary(),
       Msg :: binary().
box_open(CipherText, Nonce, PK, SK) ->
    case iolist_size(CipherText) of
        K when K =< ?BOX_SIZE ->
           R =
            case enacl_nif:crypto_box_open_b([p_box_zerobytes(), CipherText], Nonce, PK, SK) of
              {error, Err} -> {error, Err};
              Bin when is_binary(Bin) -> {ok, Bin}
            end,
           bump(R, ?BOX_REDUCTIONS, ?BOX_SIZE, K);
        _ ->
            case enacl_nif:crypto_box_open([p_box_zerobytes(), CipherText], Nonce, PK, SK) of
              {error, Err} -> {error, Err};
              Bin when is_binary(Bin) -> {ok, Bin}
            end
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
            bump(enacl_nif:crypto_box_afternm_b([p_zerobytes(), Msg], Nonce, Key),
            	?BOX_AFTERNM_REDUCTIONS, ?BOX_AFTERNM_SIZE, K);
        _ ->
            enacl_nif:crypto_box_afternm([p_zerobytes(), Msg], Nonce, Key)
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
            case enacl_nif:crypto_box_open_afternm_b([p_box_zerobytes(), CipherText], Nonce, Key) of
              {error, Err} -> {error, Err};
              Bin when is_binary(Bin) -> {ok, Bin}
            end,
           bump(R, ?BOX_AFTERNM_REDUCTIONS, ?BOX_AFTERNM_SIZE, K);
        _ ->
            case enacl_nif:crypto_box_open_afternm([p_box_zerobytes(), CipherText], Nonce, Key) of
              {error, Err} -> {error, Err};
              Bin when is_binary(Bin) -> {ok, Bin}
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
    case iolist_size(M) of
      K when K =< ?SIGN_SIZE ->
        bump(enacl_nif:crypto_sign_b(M, SK), ?SIGN_REDUCTIONS, ?SIGN_SIZE, K);
      _ ->
        enacl_nif:crypto_sign(M, SK)
    end.

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
    case iolist_size(SM) of
        K when K =< ?SIGN_SIZE ->
          R = case enacl_nif:crypto_sign_open_b(SM, PK) of
                  M when is_binary(M) -> {ok, M};
                  {error, Err} -> {error, Err}
              end,
          bump(R, ?SIGN_REDUCTIONS, ?SIGN_SIZE, byte_size(SM));
        _ ->
          case enacl_nif:crypto_sign_open(SM, PK) of
              M when is_binary(M) -> {ok, M};
              {error, Err} -> {error, Err}
          end
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
sign_detached(M, SK) -> enacl_nif:crypto_sign_detached(M, SK).

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
        true  -> {ok, M};
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
-spec seal_box(Msg, PK) -> SealedCipherText
  when Msg :: iodata(),
       PK :: binary(),
       SealedCipherText :: binary().
seal_box(Msg, PK) ->
      enacl_nif:crypto_box_seal(Msg, PK).

%% @doc seal_box_open/3 decrypts+check message integrity from an unknown sender.
%%
%% Decrypt a `SealedCipherText' which contains an ephemeral public key from another party
%% into a `Msg' using that key and your public and secret keys, `PK' and `SK'. Returns the
%% plaintext message.
%% @end
-spec seal_box_open(SealedCipherText, PK, SK) -> {ok, Msg} | {error, failed_verification}
  when SealedCipherText :: iodata(),
      PK :: binary(),
      SK :: binary(),
      Msg :: binary().
seal_box_open(SealedCipherText, PK, SK) ->
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
          bump(enacl_nif:crypto_secretbox_b([s_zerobytes(), Msg], Nonce, Key),
               ?SECRETBOX_REDUCTIONS,
               ?SECRETBOX_SIZE,
               K);
        _ ->
          enacl_nif:crypto_secretbox([s_zerobytes(), Msg], Nonce, Key)
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
          R = case enacl_nif:crypto_secretbox_open_b([s_box_zerobytes(), CipherText],
                                                     Nonce, Key) of
                  {error, Err} -> {error, Err};
                  Bin when is_binary(Bin) -> {ok, Bin}
              end,
          bump(R, ?SECRETBOX_OPEN_REDUCTIONS, ?SECRETBOX_SIZE, K);
        _ ->
          case enacl_nif:crypto_secretbox_open([s_box_zerobytes(), CipherText], Nonce, Key) of
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

%% @doc stream_nonce_size/0 returns the byte size of the nonce for streams
%% @end
-spec stream_nonce_size() -> pos_integer().
stream_nonce_size() -> enacl_nif:crypto_stream_NONCEBYTES().

%% @doc stream_key_size/0 returns the byte size of the key for streams
%% @end
-spec stream_key_size() -> pos_integer().
stream_key_size() -> enacl_nif:crypto_stream_KEYBYTES().

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
auth_key_size() -> enacl_nif:crypto_auth_KEYBYTES().

%% @doc auth_size/0 returns the byte-size of the authenticator
%% @end
-spec auth_size() -> pos_integer().
auth_size() -> enacl_nif:crypto_auth_BYTES().

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
onetime_auth_size() -> enacl_nif:crypto_onetimeauth_BYTES().

%% @doc onetime_auth_key_size/0 returns the byte-size of the onetime authentication key
%% @end
-spec onetime_auth_key_size() -> pos_integer().
onetime_auth_key_size() -> enacl_nif:crypto_onetimeauth_KEYBYTES().

%% Curve 25519 Crypto
%% ------------------
%% @doc curve25519_scalarmult/2 does a scalar multiplication between the Secret and the BasePoint.
%% @end.
-spec curve25519_scalarmult(Secret :: binary(), BasePoint :: binary()) -> binary().
curve25519_scalarmult(Secret, BasePoint) ->
	enacl_nif:crypto_curve25519_scalarmult(Secret, BasePoint).

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
	enacl_nif:crypto_sign_ed25519_public_to_curve25519(PublicKey).

%% @doc crypto_sign_ed25519_secret_to_curve25519/1 converts a given Ed 25519 secret
%% key to a Curve 25519 secret key.
%% @end
-spec crypto_sign_ed25519_secret_to_curve25519(SecretKey :: binary()) -> binary().
crypto_sign_ed25519_secret_to_curve25519(SecretKey) ->
	enacl_nif:crypto_sign_ed25519_secret_to_curve25519(SecretKey).

-spec crypto_sign_ed25519_public_size() -> pos_integer().
crypto_sign_ed25519_public_size() ->
	enacl_nif:crypto_sign_ed25519_PUBLICKEYBYTES().

-spec crypto_sign_ed25519_secret_size() -> pos_integer().
crypto_sign_ed25519_secret_size() ->
	enacl_nif:crypto_sign_ed25519_SECRETKEYBYTES().

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
randombytes(N) when N =< ?RANDOMBYTES_SIZE ->
    bump(enacl_nif:randombytes_b(N), ?RANDOMBYTES_REDUCTIONS, ?RANDOMBYTES_SIZE, N);
randombytes(N) ->
    enacl_nif:randombytes(N).

%% Helpers
p_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()).

p_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()).

s_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_ZEROBYTES()).

s_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_BOXZEROBYTES()).

bump(Res, Budget, Max, Sz) ->
    Reds =  (Budget * Sz) div Max,
    erlang:bump_reductions(max(1, Reds)),
    Res.
