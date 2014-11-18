-module(enacl).

-export([
	hash/1,
	box_keypair/0
]).

hash(Bin) ->
	enacl_nif:crypto_hash(Bin).
	
box_keypair() ->
	enacl_nif:crypto_box_keypair().

