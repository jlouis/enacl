#ifndef ENACL_GENERICHASH_H
#define ENACL_GENERICHASH_H

#include <erl_nif.h>

int enacl_init_generic_hash_ctx(ErlNifEnv *env);

ERL_NIF_TERM enacl_crypto_generichash_BYTES(ErlNifEnv *env, int argc,
                                            const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_BYTES_MIN(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_BYTES_MAX(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[]);

ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES_MIN(ErlNifEnv *env, int argc,
                                                   const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES_MAX(ErlNifEnv *env, int argc,
                                                   const ERL_NIF_TERM argv[]);

ERL_NIF_TERM enacl_crypto_generichash(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[]);

ERL_NIF_TERM enacl_crypto_generichash_init(ErlNifEnv *env, int argc,
                                           const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_update(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[]);
ERL_NIF_TERM enacl_crypto_generichash_final(ErlNifEnv *env, int argc,
                                            const ERL_NIF_TERM argv[]);

#endif