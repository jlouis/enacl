#ifndef ENACL_ED25519_H
#define ENACL_ED25519_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_ed25519_scalarmult(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalarmult_base(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalarmult_noclamp(
        ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalarmult_base_noclamp(
        ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_add(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_sub(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_is_valid_point(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalar_reduce(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalar_negate(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalar_add(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalar_sub(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_ed25519_scalar_mul(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);
#endif
