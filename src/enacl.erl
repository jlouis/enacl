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
%%% <p><b>Note:</b>All functions will fail with a `badarg' error if given incorrect
%%% parameters.</p>
%%% @end.
-module(enacl).

%% Public key crypto
-export([
	box_keypair/0,
	box/4,
	box_open/4,
	box_nonce_size/0,
	box_public_key_bytes/0,
	box_secret_key_bytes/0,
	
	sign_keypair/0,
	sign/2,
	sign_open/2
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

%% Low-level functions
-export([
	hash/1,
	verify_16/2,
	verify_32/2
]).

%% Low level helper functions
%% -----------------

%% @doc hash/1 hashes data into a cryptographically secure checksum.
%% <p>Given a binary, `Data' of any size, run a cryptographically secure hash algorithm to
%% produce a checksum of the data. This can be used to verify the integrity of a data block
%% since the checksum have the properties of cryptographic hashes in general.</p>
%% <p>The currently selected primitive (Nov. 2014) is SHA-512</p>
%% @end
-spec hash(Data) -> Checksum
  when Data :: binary(),
       Checksum :: binary().

hash(Bin) -> enacl_nif:crypto_hash(Bin).

%% @doc verify_16/2 implements constant time 16-byte string verification
%% <p>A subtle problem in cryptographic software are timing attacks where an attacker exploits
%% early exist in string verification if the strings happen to mismatch. This allows the
%% attacker to time how long verification took and thus learn the structure of the desired
%% string to use. The verify_16/2 call will check two 16 byte strings for equality while
%% guaranteeing the equality operation is constant time.</p>
%% <p>If the strings are not exactly 16 bytes, the comparison function will fail with badarg.</p>
%% <p>Verification returns a boolean. `true' if the strings match, `false' otherwise.</p>
%% @end
-spec verify_16(binary(), binary()) -> boolean().
verify_16(X, Y) -> enacl_nif:crypto_verify_16(X, Y).

%% @doc verify_32/2 implements constant time 32-byte string verification
%% This function works as {@link verify_16/2} but does so on 32 byte strings.
%% @end
-spec verify_32(binary(), binary()) -> boolean().
verify_32(X, Y) -> enacl_nif:crypto_verify_32(X, Y).

%% Public Key Crypto
%% ---------------------
%% @doc box_keypair/0 creates a new Public/Secret keypair.
%% Generates and returns a new key pair for the Box encryption scheme. The return value is a
%% map in order to avoid using the public key as a secret key and vice versa.
%% @end.
-spec box_keypair() -> maps:map(atom(), binary()).
box_keypair() ->
	{PK, SK} = enacl_nif:crypto_box_keypair(),
	#{ public => PK, secret => SK}.

%% @doc box/4 encrypts+authenticates a message to another party.
%% Encrypt a `Msg` to the party identified by public key `PK` using your own secret key `SK` to
%% authenticate yourself. Requires a `Nonce` in addition. Returns the ciphered message.
%% @end
-spec box(Msg, Nonce, PK, SK) -> CipherText
  when Msg :: binary(),
       Nonce :: binary(),
       PK :: binary(),
       SK :: binary(),
       CipherText :: binary().
box(Msg, Nonce, PK, SK) ->
    enacl_nif:crypto_box([p_zerobytes(), Msg], Nonce, PK, SK).

%% @doc box_open/4 decrypts+verifies a message from another party.
%% Decrypt a `CipherText` into a `Msg` given the other partys public key `PK` and your secret
%% key `SK`. Also requires the same nonce as was used by the other party. Returns the plaintext
%% message.
-spec box_open(CipherText, Nonce, PK, SK) -> Msg
  when CipherText :: binary(),
       Nonce :: binary(),
       PK :: binary(),
       SK :: binary(),
       Msg :: binary().
box_open(CipherText, Nonce, PK, SK) ->
    case enacl_nif:crypto_box_open([p_box_zerobytes(), CipherText], Nonce, PK, SK) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

%% @doc box_nonce_size/0 return the byte-size of the nonce
%% Used to obtain the size of the nonce.
%% @end.
-spec box_nonce_size() -> pos_integer().
box_nonce_size() ->
	enacl_nif:crypto_box_NONCEBYTES().

%% @private
-spec box_public_key_bytes() -> pos_integer().
box_public_key_bytes() ->
	enacl_nif:crypto_box_PUBLICKEYBYTES().

%% Signatures

%% @doc sign_keypair/0 returns a signature keypair for signing
%% The returned value is a map in order to make it harder to misuse keys.
%% @end
-spec sign_keypair() -> KeyMap
  when KeyMap :: maps:map(atom(), binary()).
sign_keypair() ->
    {PK, SK} = enacl_nif:sign_keypair(),
    #{ public => PK, secret => SK}.

%% @doc sign/2 signs a message with a digital signature identified by a secret key.
%% Given a message `M' and a secret key `SK' the function will sign the message and return a signed message `SM'.
%% @end
-spec sign(M, SK) -> SM
  when
    M :: binary(),
    SK :: binary(),
    SM :: binary().
sign(M, SK) -> enacl_nif:sign(M, SK).

%% @doc sign_open/2 opens a digital signature
%% Given a signed message `SM' and a public key `PK', verify that the message has the right signature. Returns either
%% `{ok, M}' or `{error, failed_verification}' depending on the correctness of the signature.
%% @end
-spec sign_open(SM, PK) -> {ok, M} | {error, failed_verification}
  when
    SM :: binary(),
    PK :: binary(),
    M :: binary().
sign_open(SM, PK) -> enacl_nif:sign_open(SM, PK).

%% @private
-spec box_secret_key_bytes() -> pos_integer().
box_secret_key_bytes() ->
	enacl_nif:crypto_box_SECRETKEYBYTES().

secretbox(Msg, Nonce, Key) ->
    enacl_nif:crypto_secretbox([s_zerobytes(), Msg], Nonce, Key).

secretbox_open(CipherText, Nonce, Key) ->
    case enacl_nif:crypto_secretbox_open([s_box_zerobytes(), CipherText], Nonce, Key) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

secretbox_nonce_size() ->
    enacl_nif:crypto_secretbox_NONCEBYTES().

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
stream(Len, Nonce, Key) when is_integer(Len), Len >= 0 ->
    enacl_nif:crypto_stream(Len, Nonce, Key);
stream(_, _, _) -> error(badarg).

%% @doc stream_xor/3 encrypts a plaintext message into ciphertext
%% The stream_xor/3 function works by using the {@link stream/3} api to XOR a message with the cryptographic stream. The same
%% caveat applies: the nonce must be new for each sent message or the system fails to work.
%% @end
-spec stream_xor(Msg, Nonce, Key) -> CipherText
  when
    Msg :: binary(),
    Nonce :: binary(),
    Key :: binary(),
    CipherText :: binary().
stream_xor(Msg, Nonce, Key) ->
    enacl_nif:crypto_stream_xor(Msg, Nonce, Key).

%% @doc auth_key_size/0 returns the byte-size of the authentication key
%% @end
-spec auth_key_size() -> pos_integer().
auth_key_size() -> enacl_nif:crypto_auth_KEYBYTES().

%% @doc auth_size/0 returns the byte-size of the authenticator
%% @end
-spec auth_size() -> pos_integer().
auth_size() -> enacl_nif:crypto_auth_BYTES().

%% @doc auth/2 produces an authenticator (MAC) for a message
%% Given a `Msg' and a `Key' produce a MAC/Authenticator for that message. The key can be reused for several such Msg/Authenticator pairs.
%% An eavesdropper will not learn anything extra about the message structure.
%% @end
-spec auth(Msg, Key) -> Authenticator
  when
    Msg :: binary(),
    Key :: binary(),
    Authenticator :: binary().
auth(Msg, Key) -> enacl_nif:crypto_auth(Msg, Key).

%% @doc auth_verify/3 verifies an authenticator for a message
%% Given an `Authenticator', a `Msg' and a `Key'; verify that the MAC for the pair `{Msg, Key}' is really `Authenticator'. Returns
%% the value `true' if the verfication passes. Upon failure, the function returns `false'.
%% @end
-spec auth_verify(Authenticator, Msg, Key) -> boolean()
  when
    Authenticator :: binary(),
    Msg :: binary(),
    Key :: binary().
auth_verify(A, M, K) -> enacl_nif:crypto_auth_verify(A, M, K).

%% @doc onetime_auth/2 produces a ONE-TIME authenticator for a message
%% This function works like {@link auth/2} except that the key must not be used again for subsequent messages. That is, the pair
%% `{Msg, Key}' is unique and only to be used once. The advantage is primarily faster execution.
%% @end
-spec onetime_auth(Msg, Key) -> Authenticator
  when
    Msg :: binary(),
    Key :: binary(),
    Authenticator :: binary().
onetime_auth(Msg, Key) -> enacl_nif:crypto_onetimeauth(Msg, Key).

%% @doc onetime_auth_verify/3 verifies an ONE-TIME authenticator for a message
%% Given an `Authenticator', a `Msg' and a `Key'; verify that the MAC for the pair `{Msg, Key}' is really `Authenticator'. Returns
%% the value `true' if the verification passes. Upon failure, the function returns `false'. Note the caveat from {@link onetime_auth/2}
%% applies: you are not allowed to ever use the same key again for another message.
%% @end
-spec onetime_auth_verify(Authenticator, Msg, Key) -> boolean()
  when
    Authenticator :: binary(),
    Msg :: binary(),
    Key :: binary().
onetime_auth_verify(A, M, K) -> enacl_nif:crypto_onetimeauth_verify(A, M, K).

%% @doc onetime_auth_size/0 returns the number of bytes of the one-time authenticator
%% @end
-spec onetime_auth_size() -> pos_integer().
onetime_auth_size() -> enacl_nif:crypto_onetimeauth_BYTES().

%% @doc onetime_auth_key_size/0 returns the byte-size of the onetime authentication key
%% @end
-spec onetime_auth_key_size() -> pos_integer().
onetime_auth_key_size() -> enacl_nif:crypto_onetimeauth_KEYBYTES().

%% Helpers
p_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()).

p_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()).

s_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_ZEROBYTES()).

s_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_BOXZEROBYTES()).
