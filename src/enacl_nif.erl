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
         crypto_box_BEFORENMBYTES/0,

         crypto_box_keypair/0,

         crypto_box/4,
         crypto_box_open/4,

         crypto_box_beforenm/2,
         crypto_box_afternm/3,
         crypto_box_afternm_b/3,
         crypto_box_open_afternm/3,
         crypto_box_open_afternm_b/3,

         crypto_sign_PUBLICKEYBYTES/0,
         crypto_sign_SECRETKEYBYTES/0,
         crypto_sign_SEEDBYTES/0,

         crypto_sign_keypair/0,
         crypto_sign_seed_keypair/1,

         crypto_sign/2,
         crypto_sign_open/2,

         crypto_sign_detached/2,
         crypto_sign_verify_detached/3,

         crypto_sign_init/0,
         crypto_sign_update/2,
         crypto_sign_final_create/2,
         crypto_sign_final_verify/3,

         crypto_box_seal/2,
         crypto_box_seal_open/3,
         crypto_box_SEALBYTES/0
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

         crypto_stream_chacha20_KEYBYTES/0,
         crypto_stream_chacha20_NONCEBYTES/0,

         crypto_stream_chacha20/3,
         crypto_stream_chacha20_b/3,
         crypto_stream_chacha20_xor/3,
         crypto_stream_chacha20_xor_b/3,

         crypto_stream_KEYBYTES/0,
         crypto_stream_NONCEBYTES/0,

         crypto_stream/3,
         crypto_stream_b/3,
         crypto_stream_xor/3,
         crypto_stream_xor_b/3,

         crypto_aead_chacha20poly1305_ietf_encrypt/4,
         crypto_aead_chacha20poly1305_ietf_decrypt/4,
         crypto_aead_chacha20poly1305_ietf_KEYBYTES/0,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES/0,
         crypto_aead_chacha20poly1305_ietf_ABYTES/0,
         crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX/0,

         crypto_aead_xchacha20poly1305_ietf_encrypt/4,
         crypto_aead_xchacha20poly1305_ietf_decrypt/4,
         crypto_aead_xchacha20poly1305_ietf_KEYBYTES/0,
         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES/0,
         crypto_aead_xchacha20poly1305_ietf_ABYTES/0,
         crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX/0,

         crypto_auth_BYTES/0,
         crypto_auth_KEYBYTES/0,

         crypto_auth/2,
         crypto_auth_b/2,
         crypto_auth_verify/3,
         crypto_auth_verify_b/3,

         crypto_shorthash_BYTES/0,
         crypto_shorthash_KEYBYTES/0,

         crypto_shorthash/2,

         crypto_onetimeauth_BYTES/0,
         crypto_onetimeauth_KEYBYTES/0,

         crypto_onetimeauth/2,
         crypto_onetimeauth_b/2,
         crypto_onetimeauth_verify/3,
         crypto_onetimeauth_verify_b/3
        ]).

%% Curve25519
-export([
         crypto_curve25519_scalarmult/2,
         crypto_curve25519_scalarmult_base/1
        ]).

%% Ed 25519
-export([
         crypto_sign_ed25519_keypair/0,
         crypto_sign_ed25519_sk_to_pk/1,
         crypto_sign_ed25519_public_to_curve25519/1,
         crypto_sign_ed25519_secret_to_curve25519/1,
         crypto_sign_ed25519_PUBLICKEYBYTES/0,
         crypto_sign_ed25519_SECRETKEYBYTES/0
        ]).

%% Key exchange
-export([
         crypto_kx_keypair/0,
         crypto_kx_server_session_keys/3,
         crypto_kx_client_session_keys/3,
         crypto_kx_SESSIONKEYBYTES/0,
         crypto_kx_PUBLICKEYBYTES/0,
         crypto_kx_SECRETKEYBYTES/0
        ]).

%% Miscellaneous helper functions
-export([
         crypto_hash/1,
         crypto_hash_b/1,
         crypto_verify_16/2,
         crypto_verify_32/2,
         sodium_memzero/1
        ]).

%% Password Hashing - Argon2 Algorithm
-export([
         crypto_pwhash_SALTBYTES/0,
         crypto_pwhash/5,
         crypto_pwhash_str/3,
         crypto_pwhash_str_verify/2
        ]).

%% Key Derivation
-export([
         crypto_kdf_KEYBYTES/0,
         crypto_kdf_CONTEXTBYTES/0,
         crypto_kdf_derive_from_key/3
        ]).

%% Generic hash
-export([
         crypto_generichash_BYTES/0,
         crypto_generichash_BYTES_MIN/0,
         crypto_generichash_BYTES_MAX/0,
         crypto_generichash_KEYBYTES/0,
         crypto_generichash_KEYBYTES_MIN/0,
         crypto_generichash_KEYBYTES_MAX/0,
         crypto_generichash/3,
         crypto_generichash_init/2,
         crypto_generichash_update/2,
         crypto_generichash_final/1
        ]).

%% Secretstream
-export([
         crypto_secretstream_xchacha20poly1305_ABYTES/0,
         crypto_secretstream_xchacha20poly1305_HEADERBYTES/0,
         crypto_secretstream_xchacha20poly1305_KEYBYTES/0,
         crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX/0,
         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE/0,
         crypto_secretstream_xchacha20poly1305_TAG_PUSH/0,
         crypto_secretstream_xchacha20poly1305_TAG_REKEY/0,
         crypto_secretstream_xchacha20poly1305_TAG_FINAL/0,
         crypto_secretstream_xchacha20poly1305_keygen/0,
         crypto_secretstream_xchacha20poly1305_init_push/1,
         crypto_secretstream_xchacha20poly1305_push/4,
         crypto_secretstream_xchacha20poly1305_init_pull/2,
         crypto_secretstream_xchacha20poly1305_pull/3,
         crypto_secretstream_xchacha20poly1305_rekey/1
        ]).

%% Access to the RNG
-export([
         randombytes/1,
         randombytes_uint32/0,
         randombytes_uniform/1
        ]).

%% Undocumented features :>
-export([
         scramble_block_16/2
        ]).

-on_load(init/0).

init() ->
    Dir = case code:priv_dir(enacl) of
              {error, bad_name} ->
                  filename:join(
                    filename:dirname(
                      filename:dirname(
                        code:which(?MODULE))), "priv");
              D -> D
          end,
    SoName = filename:join(Dir, atom_to_list(?MODULE)),
    erlang:load_nif(SoName, 0).

crypto_generichash_BYTES() -> erlang:nif_error(nif_not_loaded).
crypto_generichash_BYTES_MIN() -> erlang:nif_error(nif_not_loaded).
crypto_generichash_BYTES_MAX() -> erlang:nif_error(nif_not_loaded).
crypto_generichash_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_generichash_KEYBYTES_MIN() -> erlang:nif_error(nif_not_loaded).
crypto_generichash_KEYBYTES_MAX() -> erlang:nif_error(nif_not_loaded).

crypto_generichash(_HashSize, _Message, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_generichash_init(_HashSize, _Key) ->  erlang:nif_error(nif_not_loaded).
crypto_generichash_update(_HashState, _Message) ->  erlang:nif_error(nif_not_loaded).
crypto_generichash_final(_HashState) ->  erlang:nif_error(nif_not_loaded).

crypto_secretstream_xchacha20poly1305_ABYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_HEADERBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_TAG_MESSAGE() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_TAG_PUSH() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_TAG_REKEY() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_TAG_FINAL() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_keygen() -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_init_push(_Key) -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_push(_Ref, _Message, _AD, _Tag) -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_init_pull(_Header, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_pull(_Ref, _CipherText, _AD) -> erlang:nif_error(nif_not_loaded).
crypto_secretstream_xchacha20poly1305_rekey(_Ref) -> erlang:nif_error(nif_not_loaded).

crypto_pwhash_SALTBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_pwhash(_Password, _Salt, _Ops, _Mem, _Alg) -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str(_Password, _Ops, _Mem) -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str_verify(_HashedPassword, _Password) -> erlang:nif_error(nif_not_loaded).

crypto_kdf_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_kdf_CONTEXTBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_kdf_derive_from_key(_MasterKey, _Context, _Id) -> erlang:nif_error(nif_not_loaded).

crypto_box_NONCEBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_box_ZEROBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_box_BOXZEROBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_box_PUBLICKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_box_SECRETKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_box_BEFORENMBYTES() -> erlang:nif_error(nif_not_loaded).

crypto_box_keypair() -> erlang:nif_error(nif_not_loaded).
crypto_box(_PaddedMsg, _Nonce, _PK, _SK) -> erlang:nif_error(nif_not_loaded).
crypto_box_open(_CipherText, _Nonce, _PK, _SK) -> erlang:nif_error(nif_not_loaded).

crypto_box_beforenm(_PK, _SK) -> erlang:nif_error(nif_not_loaded).
crypto_box_afternm(_M, _Nonce, _K) -> erlang:nif_error(nif_not_loaded).
crypto_box_afternm_b(_M, _Nonce, _K) -> erlang:nif_error(nif_not_loaded).
crypto_box_open_afternm(_CipherText, _Nonce, _K) -> erlang:nif_error(nif_not_loaded).
crypto_box_open_afternm_b(_CipherText, _Nonce, _K) -> erlang:nif_error(nif_not_loaded).

crypto_sign_PUBLICKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_sign_SECRETKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_sign_SEEDBYTES() -> erlang:nif_error(nif_not_loaded).

crypto_sign_keypair() -> erlang:nif_error(nif_not_loaded).
crypto_sign_seed_keypair(_S) -> erlang:nif_error(nif_not_loaded).
crypto_sign(_M, _SK) -> erlang:nif_error(nif_not_loaded).
crypto_sign_open(_SignedMessage, _PK) -> erlang:nif_error(nif_not_loaded).

crypto_sign_detached(_M, _SK) -> erlang:nif_error(nif_not_loaded).

crypto_sign_verify_detached(_Sig, _M, _PK) -> erlang:nif_error(nif_not_loaded).

crypto_sign_init() -> erlang:nif_error(nif_not_loaded).
crypto_sign_update(_S, _M) -> erlang:nif_error(nif_not_loaded).
crypto_sign_final_create(_S, _SK) -> erlang:nif_error(nif_not_loaded).
crypto_sign_final_verify(_State, _Sig, _PK) -> erlang:nif_error(nif_not_loaded).

crypto_box_seal(_Msg, _PK) -> erlang:nif_error(nif_not_loaded).
crypto_box_seal_open(_CipherText, _PK, _SK) -> erlang:nif_error(nif_not_loaded).
crypto_box_SEALBYTES() -> erlang:nif_error(nif_not_loaded).

crypto_secretbox_NONCEBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_ZEROBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_BOXZEROBYTES() -> erlang:nif_error(nif_not_loaded).

crypto_secretbox(_Msg, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_b(_Msg, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_open(_Msg, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_secretbox_open_b(_Msg, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_stream_chacha20_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_stream_chacha20_NONCEBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_stream_chacha20(_Bytes, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_chacha20_b(_Bytes, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_chacha20_xor(_M, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_chacha20_xor_b(_M, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_stream_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_stream_NONCEBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_stream(_Bytes, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_b(_Bytes, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_xor(_M, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_stream_xor_b(_M, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_aead_chacha20poly1305_ietf_encrypt(_Message, _AD, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_aead_chacha20poly1305_ietf_decrypt(_CipherText, _AD, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_aead_chacha20poly1305_ietf_KEYBYTES()                           -> erlang:nif_error(nif_not_loaded).
crypto_aead_chacha20poly1305_ietf_NPUBBYTES()                          -> erlang:nif_error(nif_not_loaded).
crypto_aead_chacha20poly1305_ietf_ABYTES()                             -> erlang:nif_error(nif_not_loaded).
crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX()                   -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_encrypt(_Message, _AD, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_decrypt(_CipherText, _AD, _Nonce, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_KEYBYTES()                           -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_NPUBBYTES()                          -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_ABYTES()                             -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX()                   -> erlang:nif_error(nif_not_loaded).

crypto_auth_BYTES() -> erlang:nif_error(nif_not_loaded).
crypto_auth_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_auth(_Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_auth_b(_Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_auth_verify(_Authenticator, _Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_auth_verify_b(_Authenticator, _Msg, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_shorthash_BYTES() -> erlang:nif_error(nif_not_loaded).
crypto_shorthash_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_shorthash(_Msg, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_onetimeauth_BYTES() -> erlang:nif_error(nif_not_loaded).
crypto_onetimeauth_KEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_onetimeauth(_Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_onetimeauth_b(_Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_onetimeauth_verify(_Authenticator, _Msg, _Key) -> erlang:nif_error(nif_not_loaded).
crypto_onetimeauth_verify_b(_Authenticator, _Msg, _Key) -> erlang:nif_error(nif_not_loaded).

crypto_curve25519_scalarmult(_Secret, _BasePoint) -> erlang:nif_error(nif_not_loaded).
crypto_curve25519_scalarmult_base(_Secret) -> erlang:nif_error(nif_not_loaded).

crypto_sign_ed25519_keypair() -> erlang:nif_error(nif_not_loaded).
crypto_sign_ed25519_sk_to_pk(_SecretKey) -> erlang:nif_error(nif_not_loaded).
crypto_sign_ed25519_public_to_curve25519(_PublicKey) -> erlang:nif_error(nif_not_loaded).
crypto_sign_ed25519_secret_to_curve25519(_SecretKey) -> erlang:nif_error(nif_not_loaded).
crypto_sign_ed25519_PUBLICKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_sign_ed25519_SECRETKEYBYTES() -> erlang:nif_error(nif_not_loaded).

crypto_hash(Input) when is_binary(Input) -> erlang:nif_error(nif_not_loaded).
crypto_hash_b(Input) when is_binary(Input) -> erlang:nif_error(nif_not_loaded).
crypto_verify_16(_X, _Y) -> erlang:nif_error(nif_not_loaded).
crypto_verify_32(_X, _Y) -> erlang:nif_error(nif_not_loaded).
sodium_memzero(Input) when is_binary(Input) -> erlang:nif_error(nif_not_loaded).

crypto_kx_keypair() -> erlang:nif_error(nif_not_loaded).
crypto_kx_server_session_keys(_ServerPk,_ServerSk,_ClientPk) -> erlang:nif_error(nif_not_loaded).
crypto_kx_client_session_keys(_ClientPk,_ClientSk,_ServerPk) -> erlang:nif_error(nif_not_loaded).
crypto_kx_SESSIONKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_kx_PUBLICKEYBYTES() -> erlang:nif_error(nif_not_loaded).
crypto_kx_SECRETKEYBYTES() -> erlang:nif_error(nif_not_loaded).

randombytes(_RequestedSize) -> erlang:nif_error(nif_not_loaded).
randombytes_uint32() -> erlang:nif_error(nif_not_loaded).
randombytes_uniform(_UpperBound) -> erlang:nif_error(nif_not_loaded).

scramble_block_16(_Block, _Key) -> erlang:nif_error(nif_not_loaded).
