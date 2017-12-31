%%% @doc module enacl_ext implements various enacl extensions.
%%% <p>None of the extensions listed here are part of the official NaCl library.
%%% Functions may be removed without further notice if it suddenly ends up being
%%% better to do something differently than the solution given here.
%%% </p>
-module(enacl_ext).

-export([
         scramble_block_16/2
        ]).

%% Curve25519
-export([
         curve25519_keypair/0,
         curve25519_public_key/1,
         curve25519_shared/2
        ]).

%% @doc scramble_block_16/2 scrambles (encrypt) a block under a given key
%% The rules are that the block is 16 bytes and the key is 32 bytes. The block
%% is scrambled by means of the (secret) key. This makes it impossible for an
%% attacker to understand the original input for the scrambling. The intention
%% of this method is to protect counters from leaking to the outside world, by
%% scrambling them before they leave the system.
%%
%% Scrambling is done by means of the TEA algorithm (Tiny Encryption Algorithm)
%% It has known weaknesses and should probably not be used long-term going
%% forward, but CurveCP currently uses it for nonce scrambling.
%% @end
-spec scramble_block_16(binary(), binary()) -> binary().
scramble_block_16(Block, Key) ->
    enacl_nif:scramble_block_16(Block, Key).

%% Curve 25519 Crypto
%% ------------------
%% @doc curve25519_keypair/0 creates a new Public/Secret keypair.
%%
%% Generates and returns a new key pair for the Curve 25519 encryption scheme. The return value is a
%% map in order to avoid using the public key as a secret key and vice versa.
%% @end
-spec curve25519_keypair() -> #{ atom() => binary() }.
curve25519_keypair() ->
    <<B0:8/integer, B1:30/binary, B2:8/integer>> = enacl:randombytes(32),
    SK = <<(B0 band 248), B1/binary, (64 bor (B2 band 127))>>,
    PK = curve25519_public_key(SK),
    #{ public => PK, secret => SK }.

%% @doc curve25519_public_key/1 creates a public key from a given SecretKey.
%% @end
-spec curve25519_public_key(SecretKey :: binary()) -> binary().
curve25519_public_key(SecretKey) ->
    enacl:curve25519_scalarmult(SecretKey, <<9, 0:248>>).

%% @doc curve25519_shared/2 creates a new shared secret from a given SecretKey and PublicKey.
%% @end.
-spec curve25519_shared(SecretKey :: binary(), PublicKey :: binary()) -> binary().
curve25519_shared(SecretKey, PublicKey) ->
    enacl:curve25519_scalarmult(SecretKey, PublicKey).
