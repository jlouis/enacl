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
%%% @end.
-module(enacl).

%% Public key crypto
-export([
	box_keypair/0,
	box/4,
	box_open/4,
	box_nonce_size/0,
	box_public_key_bytes/0,
	box_secret_key_bytes/0
]).

%% Secret key crypto
-export([
	secretbox/3,
	secretbox_open/3,
	secretbox_nonce_size/0,
	secretbox_key_size/0
]).

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
box_keypair() ->
	enacl_nif:crypto_box_keypair().

box(Msg, Nonce, PK, SK) ->
    enacl_nif:crypto_box([p_zerobytes(), Msg], Nonce, PK, SK).
    
box_open(CipherText, Nonce, PK, SK) ->
    case enacl_nif:crypto_box_open([p_box_zerobytes(), CipherText], Nonce, PK, SK) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

box_nonce_size() ->
	enacl_nif:crypto_box_NONCEBYTES().

box_public_key_bytes() ->
	enacl_nif:crypto_box_PUBLICKEYBYTES().
	
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

%% Helpers
p_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()).
	
p_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()).

s_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_ZEROBYTES()).
	
s_box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_secretbox_BOXZEROBYTES()).
