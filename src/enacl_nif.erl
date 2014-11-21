%%% @doc module enacl_nif provides the low-level interface to the NaCl/Sodium NIFs.
%%% @end
-module(enacl_nif).

%% Public key auth
-export([
	crypto_box_keypair/0,
	crypto_box/4,
	crypto_box_open/4,
	crypto_box_NONCEBYTES/0,
	crypto_box_ZEROBYTES/0,
	crypto_box_BOXZEROBYTES/0
]).

%% Miscellaneous helper functions
-export([
	crypto_hash/1
]).

-on_load(init/0).

init() ->
	SoName = filename:join(
		case code:priv_dir(enacl) of
		    {error, bad_name} ->
		        filename:join(filename:dirname(filename:dirname(code:which(?MODULE))), "priv");
		    Dir ->
		        Dir
		end, atom_to_list(?MODULE)),
	erlang:load_nif(SoName, 0).

not_loaded() ->
    error({nif_not_loaded, ?MODULE}).

crypto_box_NONCEBYTES() -> not_loaded().
crypto_box_ZEROBYTES() -> not_loaded().
crypto_box_BOXZEROBYTES() -> not_loaded().
crypto_box_keypair() -> not_loaded().
crypto_box(_PaddedMsg, _Nonce, _PK, _SK) -> not_loaded().
crypto_box_open(_CipherText, _Nonce, _PK, _SK) -> not_loaded().

crypto_hash(Input) when is_binary(Input) -> not_loaded().


