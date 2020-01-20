#ifndef ENACL_KX_H
#define ENACL_KX_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_kx_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kx_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kx_SESSIONKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kx_keypair(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kx_server_session_keys(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kx_client_session_keys(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);

#endif
