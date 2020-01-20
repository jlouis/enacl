#ifndef ENACL_HASH_H
#define ENACL_HASH_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_shorthash_BYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_shorthash_KEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_shorthash(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_hash(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[]);
#endif