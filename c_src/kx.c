#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "kx.h"

/* Key exchange */

ERL_NIF_TERM enacl_crypto_kx_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_SECRETKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_kx_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_PUBLICKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_kx_SESSIONKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_SESSIONKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_kx_keypair(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SECRETKEYBYTES, &sk)) {
    enif_release_binary(&pk);
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_kx_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

ERL_NIF_TERM
enacl_crypto_kx_server_session_keys(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary rx, tx, server_pk, server_sk, client_pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &server_pk)) ||
      (!enif_inspect_binary(env, argv[1], &server_sk)) ||
      (!enif_inspect_binary(env, argv[2], &client_pk)) ||
      (server_pk.size != crypto_kx_PUBLICKEYBYTES) ||
      (server_sk.size != crypto_kx_SECRETKEYBYTES) ||
      (client_pk.size != crypto_kx_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &rx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &tx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_kx_server_session_keys(rx.data, tx.data, server_pk.data,
                                         server_sk.data, client_pk.data)) {
    // suspicious client public key
    return nacl_error_tuple(env, "invalid_client_public_key");
  }

  return enif_make_tuple2(env, enif_make_binary(env, &rx),
                          enif_make_binary(env, &tx));
}

ERL_NIF_TERM
enacl_crypto_kx_client_session_keys(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary rx, tx, client_pk, client_sk, server_pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &client_pk)) ||
      (!enif_inspect_binary(env, argv[1], &client_sk)) ||
      (!enif_inspect_binary(env, argv[2], &server_pk)) ||
      (client_pk.size != crypto_kx_PUBLICKEYBYTES) ||
      (client_sk.size != crypto_kx_SECRETKEYBYTES) ||
      (server_pk.size != crypto_kx_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &rx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &tx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_kx_client_session_keys(rx.data, tx.data, client_pk.data,
                                         client_sk.data, server_pk.data)) {
    // suspicious server public key
    return nacl_error_tuple(env, "invalid_server_public_key");
  }

  return enif_make_tuple2(env, enif_make_binary(env, &rx),
                          enif_make_binary(env, &tx));
}