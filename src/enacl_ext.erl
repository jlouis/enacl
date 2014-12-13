%%% @doc module enacl_ext implements various enacl extensions.
%%% <p>None of the extensions listed here are part of the official NaCl library.
%%% Things may be removed without further notice if it suddenly ends up being
%%% better to do something differently than the solution given here.
%%% </p>
-module(enacl_ext).

-export([
	scramble_block_16/2
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
