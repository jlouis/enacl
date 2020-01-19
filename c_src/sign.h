#ifndef ENACL_SIGN_H
#define ENACL_SIGN_H

#include "erl_nif.h"

int enacl_init_sign_ctx(ErlNifEnv *env);

ERL_NIF_TERM enacl_crypto_sign_init(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_update(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_final_create(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_final_verify(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);
#endif