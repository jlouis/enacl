-module(enacl_nif).

-export([
	crypto_hash/1,
	crypto_box_keypair/0
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

crypto_hash(Input) when is_binary(Input) -> error({nif_not_loaded, ?MODULE}).
crypto_box_keypair() -> error({nif_not_loaded, ?MODULE}).

