%%% @doc module enacl_nif provides the low-level interface to the NaCl/Sodium NIFs.
%%% @end
%%% @private
-module(enacl_nif).

%% Public key auth
-export([
	crypto_box_BOXZEROBYTES/0,
	crypto_box_NONCEBYTES/0,
	crypto_box_PUBLICKEYBYTES/0,
	crypto_box_SECRETKEYBYTES/0,
	crypto_box_ZEROBYTES/0,

	crypto_box/4,
	crypto_box_b/4,
	crypto_box_keypair/0,
	crypto_box_open/4,
	crypto_box_open_b/4,

	crypto_sign_PUBLICKEYBYTES/0,
	crypto_sign_SECRETKEYBYTES/0,

	crypto_sign/2,
	crypto_sign_b/2,
	crypto_sign_keypair/0,
	crypto_sign_open/2,
	crypto_sign_open_b/2
]).

%% Secret key crypto
-export([
	crypto_secretbox_BOXZEROBYTES/0,
	crypto_secretbox_KEYBYTES/0,
	crypto_secretbox_NONCEBYTES/0,
	crypto_secretbox_ZEROBYTES/0,

	crypto_secretbox/3,
	crypto_secretbox_b/3,
	crypto_secretbox_open/3,
	crypto_secretbox_open_b/3,

	crypto_stream_KEYBYTES/0,
	crypto_stream_NONCEBYTES/0,

	crypto_stream/3,
	crypto_stream_b/3,
	crypto_stream_xor/3,
	crypto_stream_xor_b/3,

	crypto_auth_BYTES/0,
	crypto_auth_KEYBYTES/0,

	crypto_auth/2,
	crypto_auth_b/2,
	crypto_auth_verify/3,
	crypto_auth_verify_b/3,

	crypto_onetimeauth_BYTES/0,
	crypto_onetimeauth_KEYBYTES/0,

	crypto_onetimeauth/2,
	crypto_onetimeauth_b/2,
	crypto_onetimeauth_verify/3,
	crypto_onetimeauth_verify_b/3
]).

%% Miscellaneous helper functions
-export([
	crypto_hash/1,
	crypto_hash_b/1,
	crypto_verify_16/2,
	crypto_verify_32/2
]).

%% Access to the RNG
-export([
	randombytes/1,
	randombytes_b/1
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
crypto_box_PUBLICKEYBYTES() -> not_loaded().
crypto_box_SECRETKEYBYTES() -> not_loaded().

crypto_box_keypair() -> not_loaded().
crypto_box(_PaddedMsg, _Nonce, _PK, _SK) -> not_loaded().
crypto_box_b(_PaddedMsg, _Nonce, _PK, _SK) -> not_loaded().
crypto_box_open(_CipherText, _Nonce, _PK, _SK) -> not_loaded().
crypto_box_open_b(_CipherText, _Nonce, _PK, _SK) -> not_loaded().

crypto_sign_PUBLICKEYBYTES() -> not_loaded().
crypto_sign_SECRETKEYBYTES() -> not_loaded().

crypto_sign_keypair() -> not_loaded().
crypto_sign(_M, _SK) -> not_loaded().
crypto_sign_b(_M, _SK) -> not_loaded().
crypto_sign_open(_SignedMessage, _PK) -> not_loaded().
crypto_sign_open_b(_SignedMessage, _PK) -> not_loaded().

crypto_secretbox_NONCEBYTES() -> not_loaded().
crypto_secretbox_ZEROBYTES() -> not_loaded().
crypto_secretbox_KEYBYTES() -> not_loaded().
crypto_secretbox_BOXZEROBYTES() -> not_loaded().

crypto_secretbox(_Msg, _Nonce, _Key) -> not_loaded().
crypto_secretbox_b(_Msg, _Nonce, _Key) -> not_loaded().
crypto_secretbox_open(_Msg, _Nonce, _Key) -> not_loaded().
crypto_secretbox_open_b(_Msg, _Nonce, _Key) -> not_loaded().

crypto_stream_KEYBYTES() -> not_loaded().
crypto_stream_NONCEBYTES() -> not_loaded().
crypto_stream(_Bytes, _Nonce, _Key) -> not_loaded().
crypto_stream_b(_Bytes, _Nonce, _Key) -> not_loaded().
crypto_stream_xor(_M, _Nonce, _Key) -> not_loaded().
crypto_stream_xor_b(_M, _Nonce, _Key) -> not_loaded().

crypto_auth_BYTES() -> not_loaded().
crypto_auth_KEYBYTES() -> not_loaded().
crypto_auth(_Msg, _Key) -> not_loaded().
crypto_auth_b(_Msg, _Key) -> not_loaded().
crypto_auth_verify(_Authenticator, _Msg, _Key) -> not_loaded().
crypto_auth_verify_b(_Authenticator, _Msg, _Key) -> not_loaded().

crypto_onetimeauth_BYTES() -> not_loaded().
crypto_onetimeauth_KEYBYTES() -> not_loaded().
crypto_onetimeauth(_Msg, _Key) -> not_loaded().
crypto_onetimeauth_b(_Msg, _Key) -> not_loaded().
crypto_onetimeauth_verify(_Authenticator, _Msg, _Key) -> not_loaded().
crypto_onetimeauth_verify_b(_Authenticator, _Msg, _Key) -> not_loaded().

crypto_hash(Input) when is_binary(Input) -> not_loaded().
crypto_hash_b(Input) when is_binary(Input) -> not_loaded().
crypto_verify_16(_X, _Y) -> not_loaded().
crypto_verify_32(_X, _Y) -> not_loaded().

randombytes(_RequestedSize) -> not_loaded().
randombytes_b(_RequestedSize) -> not_loaded().

