-module(enacl).

-export([
	box_keypair/0,
	box/4,
	box_open/4,
	box_nonce_size/0
]).

-export([
	hash/1
]).

hash(Bin) ->
	enacl_nif:crypto_hash(Bin).
	
box_keypair() ->
	enacl_nif:crypto_box_keypair().

box(Msg, Nonce, PK, SK) ->
    enacl_nif:crypto_box([zerobytes(), Msg], Nonce, PK, SK).
    
box_open(CipherText, Nonce, PK, SK) ->
    case enacl_nif:crypto_box_open([box_zerobytes(), CipherText], Nonce, PK, SK) of
        {error, Err} -> {error, Err};
        Bin when is_binary(Bin) -> {ok, Bin}
    end.

box_nonce_size() ->
	enacl_nif:crypto_box_NONCEBYTES().

%% Helpers
zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()).
	
box_zerobytes() ->
	binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()).
