#ifndef ENACL_SIGN_H
#define ENACL_SIGN_H

#include <erl_nif.h>

int enacl_init_sign_ctx(ErlNifEnv *env);

ERL_NIF_TERM enacl_crypto_sign_init(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_update(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_final_create(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_final_verify(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_ed25519_keypair(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_ed25519_sk_to_pk(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);

ERL_NIF_TERM
enacl_crypto_sign_ed25519_public_to_curve25519(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM
enacl_crypto_sign_ed25519_secret_to_curve25519(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM
enacl_crypto_sign_ed25519_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM
enacl_crypto_sign_ed25519_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_SEEDBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_keypair(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_seed_keypair(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign(ErlNifEnv *env, int argc,
                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_open(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_sign_detached(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]);

ERL_NIF_TERM
enacl_crypto_sign_verify_detached(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]);

#endif